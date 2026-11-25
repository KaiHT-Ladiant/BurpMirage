'use strict';

/**
 * BurpMirage Winsock hooks — Frida 17+ compatible.
 *
 * Frida 17 removed static Module.findExportByName / getExportByName.
 * Use: Process.getModuleByName('ws2_32.dll').findExportByName('send')
 */

var hooked = {
  send: true,
  recv: true
};

// Injected at extract-time by FridaController (defaults if missing).
var modeProxyForce = (typeof __BM_MODE_PROXY !== 'undefined') ? !!__BM_MODE_PROXY : true;
var modeSocketMirage = (typeof __BM_MODE_SOCKET !== 'undefined') ? !!__BM_MODE_SOCKET : true;
var modeTlsUnpin = (typeof __BM_MODE_TLS_UNPIN !== 'undefined') ? !!__BM_MODE_TLS_UNPIN : true;
var burpProxyHost = (typeof __BM_PROXY_HOST !== 'undefined') ? ('' + __BM_PROXY_HOST) : '127.0.0.1';
var burpProxyPort = (typeof __BM_PROXY_PORT !== 'undefined') ? (__BM_PROXY_PORT | 0) : 8800;
var proxyForceInstalled = false;
var proxyFnsHooked = {};
var socketHooksInstalled = false;
var tlsUnpinInstalled = false;
var tlsUnpinHooked = {};
var socketHandles = {}; // HANDLE/SOCKET string keys — Chromium often uses WriteFile/ReadFile on sockets
var pendingOverlappedReads = {}; // overlapped ptr -> { h, buf }
// BoringSSL: enum ssl_verify_result_t { ssl_verify_ok = 0, ssl_verify_invalid = 1, ssl_verify_retry = 2 }
var boringSslVerifyOk = null;

var packetSeq = 0;
var lastSocketFd = -1;
var ws2 = null;
var repeaterWait = null; // { fd: number, until: number }
var suppressHook = false; // true while Repeater inject calls send()

function nextId() {
  packetSeq = (packetSeq + 1) >>> 0;
  return 'p-' + Process.id + '-' + packetSeq + '-' + Date.now();
}

function getWs2() {
  if (ws2 !== null) {
    return ws2;
  }
  ws2 = Process.findModuleByName('ws2_32.dll');
  if (ws2 === null) {
    // Case / load-order fallback
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
      if (modules[i].name.toLowerCase() === 'ws2_32.dll') {
        ws2 = modules[i];
        break;
      }
    }
  }
  return ws2;
}

function resolveExport(name) {
  var mod = getWs2();
  if (mod === null) {
    return null;
  }
  if (typeof mod.findExportByName === 'function') {
    return mod.findExportByName(name);
  }
  if (typeof mod.getExportByName === 'function') {
    try {
      return mod.getExportByName(name);
    } catch (e) {
      return null;
    }
  }
  // Pre-Frida-17 fallback
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName('ws2_32.dll', name);
  }
  return null;
}

function readBytes(ptrVal, length) {
  if (length <= 0 || ptrVal === null || ptrVal.isNull()) {
    return [];
  }
  var ab;
  if (typeof ptrVal.readByteArray === 'function') {
    ab = ptrVal.readByteArray(length);
  } else {
    ab = Memory.readByteArray(ptrVal, length);
  }
  return Array.from(new Uint8Array(ab));
}

function writeBytes(ptrVal, bytes) {
  if (!bytes || bytes.length === 0 || ptrVal === null || ptrVal.isNull()) {
    return 0;
  }
  if (typeof ptrVal.writeByteArray === 'function') {
    ptrVal.writeByteArray(bytes);
  } else {
    Memory.writeByteArray(ptrVal, bytes);
  }
  return bytes.length;
}

function peerOf(fd) {
  try {
    var getpeernamePtr = resolveExport('getpeername');
    if (getpeernamePtr === null) {
      return 'fd:' + fd;
    }
    var getpeername = new NativeFunction(getpeernamePtr, 'int', ['int', 'pointer', 'pointer']);
    var sa = Memory.alloc(128);
    var len = Memory.alloc(4);
    len.writeU32(128);
    if (getpeername(fd, sa, len) !== 0) {
      return 'fd:' + fd;
    }
    var family = sa.readU16();
    if (family === 2) {
      var port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
      return sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' +
        sa.add(6).readU8() + '.' + sa.add(7).readU8() + ':' + port;
    }
    return 'fd:' + fd;
  } catch (e) {
    return 'fd:' + fd;
  }
}

/** Mode A→Burp hop: keep Mode B on for other TCP, but don't Mirage-intercept the proxy socket. */
function isBurpProxyPeer(peer) {
  if (!peer || peer.indexOf(':') < 0) {
    return false;
  }
  var wantHost = ('' + burpProxyHost).toLowerCase();
  var wantPort = '' + (burpProxyPort | 0);
  var idx = peer.lastIndexOf(':');
  var host = peer.substring(0, idx).toLowerCase();
  var port = peer.substring(idx + 1);
  if (port !== wantPort) {
    return false;
  }
  if (host === wantHost) {
    return true;
  }
  // localhost aliases
  if ((wantHost === '127.0.0.1' || wantHost === 'localhost') &&
      (host === '127.0.0.1' || host === 'localhost' || host === '::1')) {
    return true;
  }
  return false;
}

function requestDecision(direction, api, fd, buf, length) {
  var peer = peerOf(fd | 0);
  // A+B together: HTTP via Burp stays in Proxy history; raw TCP still goes through Mirage.
  if (isBurpProxyPeer(peer)) {
    return { action: 'forward', data: null };
  }
  var id = nextId();
  var bytes = readBytes(buf, length);
  var payload = {
    type: 'packet',
    id: id,
    direction: direction,
    api: api,
    peer: peer,
    fd: fd | 0,
    data: bytes
  };

  // Repeater: first RECV after inject is also reported as response (any fd)
  if (direction === 'recv' && repeaterWait) {
    if (Date.now() <= repeaterWait.until) {
      var fdOk = (repeaterWait.fd < 0) || (repeaterWait.fd === (fd | 0));
      if (fdOk) {
        send({
          type: 'repeater_response',
          requestId: repeaterWait.requestId || '',
          peer: payload.peer,
          fd: fd | 0,
          data: bytes
        });
        repeaterWait = null;
      }
    } else {
      repeaterWait = null;
    }
  }

  var response = { action: 'forward', data: null };
  send(payload);
  // Frida script.post({type, payload}) delivers the whole message to recv().
  // Decision lives in value.payload - using value itself left action/data undefined,
  // so applyInPlace kept the original buffer (edits never reached the wire).
  recv(id, function (value) {
    if (!value) {
      return;
    }
    if (value.payload !== undefined && value.payload !== null) {
      response = value.payload;
    } else if (value.action !== undefined) {
      response = value;
    }
  }).wait();
  return response;
}

function applyInPlace(buf, capacity, decision) {
  if (!decision || decision.action === 'drop') {
    return { drop: true, length: 0 };
  }
  if (decision.data && decision.data.length !== undefined) {
    var n = Math.min(decision.data.length, capacity);
    writeBytes(buf, decision.data.slice(0, n));
    // Clear stale bytes past the logical wire length.
    for (var i = n; i < capacity; i++) {
      buf.add(i).writeU8(0);
    }
    return { drop: false, length: n, fullLength: decision.data.length };
  }
  return { drop: false, length: capacity };
}

rpc.exports = {
  configure: function (cfg) {
    if (cfg.hookSend !== undefined) hooked.send = !!cfg.hookSend;
    if (cfg.hookRecv !== undefined) hooked.recv = !!cfg.hookRecv;
    if (cfg.modeProxyForce !== undefined) modeProxyForce = !!cfg.modeProxyForce;
    if (cfg.modeSocketMirage !== undefined) modeSocketMirage = !!cfg.modeSocketMirage;
    if (cfg.modeTlsUnpin !== undefined) modeTlsUnpin = !!cfg.modeTlsUnpin;
    if (cfg.burpProxyHost) burpProxyHost = '' + cfg.burpProxyHost;
    if (cfg.burpProxyPort !== undefined) burpProxyPort = cfg.burpProxyPort | 0;
    if (modeProxyForce && !proxyForceInstalled) {
      installProxyForce();
    }
    if (modeSocketMirage && !socketHooksInstalled) {
      installSocketHooks();
    }
    if (modeTlsUnpin && !tlsUnpinInstalled) {
      installTlsUnpin();
    }
    return {
      modeProxyForce: modeProxyForce,
      modeSocketMirage: modeSocketMirage,
      modeTlsUnpin: modeTlsUnpin,
      burpProxy: burpProxyHost + ':' + burpProxyPort
    };
  },
  inject: function (bytes, peerHint, waitResponse, requestId) {
    if (!bytes || !bytes.length) {
      return -1;
    }
    // Always match next RECV on any fd (raw apps often multiplex)
    if (waitResponse) {
      repeaterWait = {
        fd: -1,
        until: Date.now() + 20000,
        requestId: requestId || ''
      };
    }
    if (lastSocketFd < 0) {
      return -3;
    }
    var sendPtr = resolveExport('send');
    if (sendPtr === null) {
      return -2;
    }
    var sendFn = new NativeFunction(sendPtr, 'int', ['int', 'pointer', 'int', 'int']);
    var mem = Memory.alloc(bytes.length);
    writeBytes(mem, bytes);
    suppressHook = true;
    var rc;
    try {
      rc = sendFn(lastSocketFd, mem, bytes.length, 0);
    } finally {
      suppressHook = false;
    }
    return rc;
  },
  ping: function () {
    return 'pong:' + Process.id;
  }
};

function hookSendLike(name) {
  var addr = resolveExport(name);
  if (addr === null) {
    console.log('[BurpMirage] skip (not found): ' + name);
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      if (suppressHook) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.fd = args[0].toInt32();
      this.buf = args[1];
      this.len = args[2].toInt32();
      this.drop = false;
      lastSocketFd = this.fd;
      noteSocketHandle(args[0]);

      if (!hooked.send || this.len <= 0) {
        return;
      }
      var decision = requestDecision('send', name, this.fd, this.buf, this.len);
      var applied = applyInPlace(this.buf, this.len, decision);
      if (applied.drop) {
        this.drop = true;
      } else if (decision.data) {
        args[2] = ptr(applied.length);
      }
    },
    onLeave: function (retval) {
      if (this.skip) {
        return;
      }
      if (this.drop) {
        retval.replace(0);
      }
    }
  });
  console.log('[BurpMirage] hooked ' + name);
}

function hookRecvLike(name) {
  var addr = resolveExport(name);
  if (addr === null) {
    console.log('[BurpMirage] skip (not found): ' + name);
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      lastSocketFd = this.fd;
      noteSocketHandle(args[0]);
    },
    onLeave: function (retval) {
      if (!hooked.recv) {
        return;
      }
      var got = retval.toInt32();
      if (got <= 0) {
        return;
      }
      var decision = requestDecision('recv', name, this.fd, this.buf, got);
      var applied = applyInPlace(this.buf, got, decision);
      if (applied.drop) {
        retval.replace(0);
      } else if (decision.data) {
        retval.replace(applied.length);
      }
    }
  });
  console.log('[BurpMirage] hooked ' + name);
}

function wsabufLen(lpBuffers) {
  return lpBuffers.readU32();
}

function wsabufPtr(lpBuffers) {
  return lpBuffers.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
}

function hookWSARecv() {
  var addr = resolveExport('WSARecv');
  if (addr === null) {
    console.log('[BurpMirage] skip (not found): WSARecv');
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.s = args[0].toInt32();
      this.lpBuffers = args[1];
      this.count = args[2].toInt32();
      this.lpBytes = args[3];
      this.lpOverlapped = args[5];
      lastSocketFd = this.s;
      noteSocketHandle(args[0]);
      // Overlapped / IOCP path: bytes not ready onLeave — skip intercept for now
      this.async = !this.lpOverlapped.isNull();
    },
    onLeave: function (retval) {
      if (!hooked.recv || this.async) {
        return;
      }
      if (retval.toInt32() !== 0) {
        return;
      }
      if (this.count < 1 || this.lpBytes.isNull()) {
        return;
      }
      var got = this.lpBytes.readU32();
      if (got <= 0) {
        return;
      }
      var buf = wsabufPtr(this.lpBuffers);
      var cap = wsabufLen(this.lpBuffers);
      var decision = requestDecision('recv', 'WSARecv', this.s, buf, Math.min(got, cap));
      var applied = applyInPlace(buf, Math.min(got, cap), decision);
      if (applied.drop) {
        this.lpBytes.writeU32(0);
      } else if (decision.data) {
        this.lpBytes.writeU32(applied.length);
      }
    }
  });
  console.log('[BurpMirage] hooked WSARecv (sync)');
}

function moduleLoaded(name) {
  return Process.findModuleByName(name) !== null
      || Process.findModuleByName(name.toUpperCase()) !== null
      || Process.findModuleByName(name.toLowerCase()) !== null;
}

function detectChromiumFamily() {
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    var n = mods[i].name.toLowerCase();
    if (n === 'chrome.dll' || n === 'libcef.dll' || n === 'msedge.dll'
        || n.indexOf('libcef') >= 0 || n === 'nw.dll'
        || (n.indexOf('electron') >= 0 && n.endsWith('.dll'))) {
      return mods[i].name;
    }
  }
  return null;
}

function detectAndAnnounce() {
  var winhttp = moduleLoaded('winhttp.dll');
  var wininet = moduleLoaded('wininet.dll');
  var ws2 = moduleLoaded('ws2_32.dll');
  var chromium = detectChromiumFamily();
  var hint;
  if (chromium) {
    hint = 'Chromium/CEF (' + chromium + ') — use Inject Group (Renderer/Main/NetworkService). '
        + 'Single NetworkService is often empty (sockets may live on Renderer). '
        + 'Mode A WinHTTP is usually ineffective here; Mode B hooks send+WriteFile.';
  } else if ((winhttp || wininet) && ws2) {
    hint = 'HTTP stack + Winsock detected — recommend Mode A+B (both ON)';
  } else if (winhttp || wininet) {
    hint = 'WinHTTP/WinInet detected — recommend Mode A (Burp Proxy Force)';
  } else if (ws2) {
    hint = 'Winsock only — recommend Mode B (Mirage Socket Intercept)';
  } else {
    hint = 'No WinHTTP/WinInet/ws2_32 yet — hooks will attach when modules load';
  }
  send({
    type: 'event',
    message: 'detect: winhttp=' + winhttp + ' wininet=' + wininet
        + ' ws2=' + ws2 + ' chromium=' + (chromium || 'no') + ' | ' + hint
  });
}

function proxyString() {
  return burpProxyHost + ':' + burpProxyPort;
}

function resolveModExport(mod, name) {
  if (!mod) return null;
  try {
    if (typeof mod.findExportByName === 'function') {
      var a = mod.findExportByName(name);
      if (a !== null && !a.isNull()) return a;
    }
  } catch (e) {}
  try {
    if (typeof Module.findExportByName === 'function') {
      var b = Module.findExportByName(mod.name, name);
      if (b !== null && !b.isNull()) return b;
    }
  } catch (e2) {}
  return null;
}

function markTlsHook(key) {
  if (tlsUnpinHooked[key]) return false;
  tlsUnpinHooked[key] = true;
  return true;
}

function ensureBoringVerifyOkCallback() {
  if (boringSslVerifyOk !== null) return boringSslVerifyOk;
  // int callback(SSL *ssl, uint8_t *out_alert) → ssl_verify_ok (0)
  boringSslVerifyOk = new NativeCallback(function (ssl, outAlert) {
    return 0;
  }, 'int', ['pointer', 'pointer']);
  return boringSslVerifyOk;
}

function hookBoringSslSetCustomVerify(mod, exportName) {
  var addr = resolveModExport(mod, exportName);
  if (addr === null) return false;
  var key = mod.name + '!' + exportName;
  if (!markTlsHook(key)) return true;
  var okCb = ensureBoringVerifyOkCallback();
  Interceptor.attach(addr, {
    onEnter: function (args) {
      // SSL_CTX_set_custom_verify(ctx, mode, callback) / SSL_set_custom_verify(ssl, mode, callback)
      args[2] = okCb;
    }
  });
  console.log('[BurpMirage] TLS Unpin hooked ' + key);
  return true;
}

function hookSslSetVerify(mod, exportName) {
  var addr = resolveModExport(mod, exportName);
  if (addr === null) return false;
  var key = mod.name + '!' + exportName;
  if (!markTlsHook(key)) return true;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      // SSL_CTX_set_verify(ctx, mode, callback) — force SSL_VERIFY_NONE (0), drop callback
      args[1] = ptr(0);
      args[2] = ptr(0);
    }
  });
  console.log('[BurpMirage] TLS Unpin hooked ' + key);
  return true;
}

function chromiumCandidateModules() {
  var out = [];
  var seen = {};
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    var n = m.name.toLowerCase();
    var hit = (i === 0)
        || n === 'chrome.dll' || n === 'libcef.dll' || n === 'msedge.dll' || n === 'nw.dll'
        || n.indexOf('libcef') >= 0 || n.indexOf('chrome') >= 0
        || n.indexOf('msedge') >= 0 || n.indexOf('electron') >= 0
        || n.indexOf('amaranth') >= 0 || n.indexOf('douzone') >= 0
        || n.indexOf('ssl') >= 0 || n.indexOf('boring') >= 0
        || n === 'libssl.dll' || n === 'ssleay32.dll' || n === 'libssl-1_1-x64.dll'
        || n === 'libssl-3.dll' || n === 'libssl-3-x64.dll';
    if (hit && !seen[n]) {
      seen[n] = true;
      out.push(m);
    }
  }
  return out;
}

function findSymbolAddresses(mod, name) {
  var addrs = [];
  var exp = resolveModExport(mod, name);
  if (exp !== null) addrs.push(exp);
  try {
    if (typeof mod.enumerateSymbols === 'function') {
      var syms = mod.enumerateSymbols();
      for (var i = 0; i < syms.length; i++) {
        var s = syms[i];
        if (s.name === name || (s.name && s.name.indexOf(name) !== -1)) {
          addrs.push(s.address);
        }
      }
    }
  } catch (e) {}
  try {
    if (typeof DebugSymbol !== 'undefined' && DebugSymbol.findFunctionsMatching) {
      var found = DebugSymbol.findFunctionsMatching('*' + name + '*');
      for (var j = 0; j < found.length; j++) {
        addrs.push(found[j]);
      }
    }
  } catch (e2) {}
  // de-dupe
  var uniq = [];
  var seen = {};
  for (var k = 0; k < addrs.length; k++) {
    var key = '' + addrs[k];
    if (!seen[key]) {
      seen[key] = true;
      uniq.push(addrs[k]);
    }
  }
  return uniq;
}

function hookBoringSslAtAddresses(mod, exportName, customVerify) {
  var addrs = findSymbolAddresses(mod, exportName);
  if (!addrs.length) return 0;
  var n = 0;
  for (var i = 0; i < addrs.length; i++) {
    var key = mod.name + '!' + exportName + '@' + addrs[i];
    if (!markTlsHook(key)) continue;
    if (customVerify) {
      var okCb = ensureBoringVerifyOkCallback();
      Interceptor.attach(addrs[i], {
        onEnter: function (args) {
          args[2] = okCb;
        }
      });
    } else {
      Interceptor.attach(addrs[i], {
        onEnter: function (args) {
          args[1] = ptr(0);
          args[2] = ptr(0);
        }
      });
    }
    console.log('[BurpMirage] TLS Unpin hooked ' + key);
    n++;
  }
  return n;
}

function scanBoringSslHooks() {
  var count = 0;
  var mods = chromiumCandidateModules();
  for (var i = 0; i < mods.length; i++) {
    var mod = mods[i];
    count += hookBoringSslAtAddresses(mod, 'SSL_CTX_set_custom_verify', true);
    count += hookBoringSslAtAddresses(mod, 'SSL_set_custom_verify', true);
    count += hookBoringSslAtAddresses(mod, 'SSL_CTX_set_verify', false);
    count += hookBoringSslAtAddresses(mod, 'SSL_set_verify', false);
  }
  return count;
}

var sslIoHookCount = 0;

/**
 * Mode B at TLS layer — Chromium often never hits ws2 send() with plaintext.
 * SSL_write/SSL_read (BoringSSL) feeds Mirage History even when sockets use IOCP.
 */
function installSslTrafficHooks() {
  var mods = chromiumCandidateModules();
  var before = sslIoHookCount;
  for (var i = 0; i < mods.length; i++) {
    sslIoHookCount += hookSslWriteLike(mods[i], 'SSL_write');
    sslIoHookCount += hookSslReadLike(mods[i], 'SSL_read');
  }
  var added = sslIoHookCount - before;
  if (added > 0) {
    send({ type: 'event', message: 'Mode B SSL_read/write hooks +' + added + ' (total=' + sslIoHookCount + ') pid=' + Process.id });
  }
  return added;
}

function hookSslWriteLike(mod, exportName) {
  var addrs = findSymbolAddresses(mod, exportName);
  if (!addrs.length) return 0;
  var n = 0;
  for (var i = 0; i < addrs.length; i++) {
    var key = mod.name + '!' + exportName + '@' + addrs[i] + '#io';
    if (!markTlsHook(key)) continue;
    Interceptor.attach(addrs[i], {
      onEnter: function (args) {
        if (!hooked.send || suppressHook) {
          this.skip = true;
          return;
        }
        this.skip = false;
        this.buf = args[1];
        this.len = args[2].toInt32();
        if (this.len <= 0) return;
        var decision = requestDecision('send', exportName, -1, this.buf, this.len);
        var applied = applyInPlace(this.buf, this.len, decision);
        this.drop = applied.drop;
        if (!this.drop && decision && decision.data) {
          args[2] = ptr(applied.length);
        }
      },
      onLeave: function (retval) {
        if (this.skip) return;
        if (this.drop) {
          retval.replace(0);
        }
      }
    });
    console.log('[BurpMirage] hooked ' + key);
    n++;
  }
  return n;
}

function hookSslReadLike(mod, exportName) {
  var addrs = findSymbolAddresses(mod, exportName);
  if (!addrs.length) return 0;
  var n = 0;
  for (var i = 0; i < addrs.length; i++) {
    var key = mod.name + '!' + exportName + '@' + addrs[i] + '#io';
    if (!markTlsHook(key)) continue;
    Interceptor.attach(addrs[i], {
      onEnter: function (args) {
        this.buf = args[1];
      },
      onLeave: function (retval) {
        if (!hooked.recv) return;
        var got = retval.toInt32();
        if (got <= 0) return;
        var decision = requestDecision('recv', exportName, -1, this.buf, got);
        var applied = applyInPlace(this.buf, got, decision);
        if (applied.drop) {
          retval.replace(0);
        } else if (decision && decision.data) {
          retval.replace(applied.length);
        }
      }
    });
    console.log('[BurpMirage] hooked ' + key);
    n++;
  }
  return n;
}

function hookCertVerifyCertificateChainPolicy() {
  var mod = Process.findModuleByName('crypt32.dll');
  if (!mod) return false;
  var addr = resolveModExport(mod, 'CertVerifyCertificateChainPolicy');
  if (addr === null) return false;
  var key = 'crypt32.dll!CertVerifyCertificateChainPolicy';
  if (!markTlsHook(key)) return true;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.statusPtr = args[3];
    },
    onLeave: function (retval) {
      try {
        if (this.statusPtr && !this.statusPtr.isNull()) {
          // CERT_CHAIN_POLICY_STATUS.dwError at offset 4
          this.statusPtr.add(4).writeU32(0);
        }
      } catch (e) {}
      retval.replace(ptr(1));
    }
  });
  console.log('[BurpMirage] TLS Unpin hooked ' + key);
  return true;
}

function hookWinVerifyTrust() {
  var mod = Process.findModuleByName('wintrust.dll');
  if (!mod) return false;
  var addr = resolveModExport(mod, 'WinVerifyTrust');
  if (addr === null) return false;
  var key = 'wintrust.dll!WinVerifyTrust';
  if (!markTlsHook(key)) return true;
  Interceptor.attach(addr, {
    onLeave: function (retval) {
      retval.replace(ptr(0)); // ERROR_SUCCESS / trust OK
    }
  });
  console.log('[BurpMirage] TLS Unpin hooked ' + key);
  return true;
}

function armTlsUnpinLateLoad() {
  var key = 'kernel32!LoadLibrary*';
  if (!markTlsHook(key)) return;
  var loaders = ['LoadLibraryW', 'LoadLibraryExW', 'LoadLibraryA', 'LoadLibraryExA'];
  var k32 = Process.findModuleByName('kernel32.dll');
  if (!k32) return;
  loaders.forEach(function (ln) {
    var p = resolveModExport(k32, ln);
    if (p === null) return;
    Interceptor.attach(p, {
      onLeave: function (retval) {
        if (!modeTlsUnpin || retval.isNull()) return;
        try {
          scanBoringSslHooks();
          hookCertVerifyCertificateChainPolicy();
          hookWinVerifyTrust();
          if (modeSocketMirage) {
            installSslTrafficHooks();
          }
        } catch (e) {}
      }
    });
  });
}

/**
 * Mode C — TLS Unpin: accept Burp (or any) MITM cert for Chromium/BoringSSL + Schannel paths.
 * Does not by itself route traffic to Burp; combine with Mode A (process-local proxy fake).
 */
function installTlsUnpin() {
  if (tlsUnpinInstalled) {
    return;
  }
  tlsUnpinInstalled = true;
  var boring = 0;
  try {
    boring = scanBoringSslHooks();
  } catch (e) {
    send({ type: 'event', message: 'Mode C BoringSSL scan error: ' + e });
  }
  var schannel = false;
  var wintrust = false;
  try {
    schannel = hookCertVerifyCertificateChainPolicy();
  } catch (e2) {}
  try {
    wintrust = hookWinVerifyTrust();
  } catch (e3) {}
  try {
    armTlsUnpinLateLoad();
  } catch (e4) {}

  send({
    type: 'event',
    message: 'Mode C TLS Unpin armed — boringSslExports=' + boring
        + ' CertVerifyChain=' + schannel
        + ' WinVerifyTrust=' + wintrust
        + ' | Chromium: use Inject Group (Renderer/Main/NetworkService); pin/custom-verify bypassed when hooked'
  });
}

function installProxyForce() {
  if (proxyForceInstalled) {
    return;
  }
  var proxy = proxyString();
  var hookedAny = false;

  function hookWinHttpOpen(name) {
    if (proxyFnsHooked[name]) return;
    var mod = Process.findModuleByName('winhttp.dll');
    if (!mod) return;
    var addr = null;
    if (typeof mod.findExportByName === 'function') {
      addr = mod.findExportByName(name);
    }
    if (addr === null && typeof Module.findExportByName === 'function') {
      addr = Module.findExportByName('winhttp.dll', name);
    }
    if (addr === null) return;
    // WinHttpOpen(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR bypass, DWORD flags)
    var WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;
    var proxyBuf = Memory.allocUtf16String(proxy);
    var bypassBuf = Memory.allocUtf16String('<local>');
    Interceptor.attach(addr, {
      onEnter: function (args) {
        args[1] = ptr(WINHTTP_ACCESS_TYPE_NAMED_PROXY);
        args[2] = proxyBuf;
        args[3] = bypassBuf;
      }
    });
    proxyFnsHooked[name] = true;
    console.log('[BurpMirage] Proxy Force hooked ' + name + ' -> ' + proxy);
    hookedAny = true;
  }

  function hookInternetOpen(name, unicode) {
    if (proxyFnsHooked[name]) return;
    var mod = Process.findModuleByName('wininet.dll');
    if (!mod) return;
    var addr = null;
    if (typeof mod.findExportByName === 'function') {
      addr = mod.findExportByName(name);
    }
    if (addr === null && typeof Module.findExportByName === 'function') {
      addr = Module.findExportByName('wininet.dll', name);
    }
    if (addr === null) return;
    // InternetOpen(agent, accessType, proxy, bypass, flags) — accessType PROXY = 3
    var INTERNET_OPEN_TYPE_PROXY = 3;
    var proxyBuf = unicode ? Memory.allocUtf16String(proxy) : Memory.allocUtf8String(proxy);
    var bypassBuf = unicode ? Memory.allocUtf16String('<local>') : Memory.allocUtf8String('<local>');
    Interceptor.attach(addr, {
      onEnter: function (args) {
        args[1] = ptr(INTERNET_OPEN_TYPE_PROXY);
        args[2] = proxyBuf;
        args[3] = bypassBuf;
      }
    });
    console.log('[BurpMirage] Proxy Force hooked ' + name + ' -> ' + proxy);
    hookedAny = true;
  }

  hookWinHttpOpen('WinHttpOpen');
  hookInternetOpen('InternetOpenW', true);
  hookInternetOpen('InternetOpenA', false);

  // Chromium/Electron: process-local only — hook Get* APIs inside this PID.
  // Never call WinHttpSetDefaultProxyConfiguration (that is OS/user-wide).
  function hookWinHttpIeProxyConfig() {
    var mod = Process.findModuleByName('winhttp.dll');
    if (!mod) return false;
    var addr = resolveModExport(mod, 'WinHttpGetIEProxyConfigForCurrentUser');
    if (addr === null) return false;
    if (proxyFnsHooked['WinHttpGetIEProxyConfigForCurrentUser']) return true;
    var proxyBuf = Memory.allocUtf16String(proxy);
    var bypassBuf = Memory.allocUtf16String('localhost;127.*;<local>');
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.cfg = args[0];
      },
      onLeave: function (retval) {
        try {
          if (this.cfg.isNull()) return;
          // WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
          this.cfg.writeU32(0); // fAutoDetect = FALSE
          this.cfg.add(Process.pointerSize).writePointer(ptr(0));
          this.cfg.add(Process.pointerSize * 2).writePointer(proxyBuf);
          this.cfg.add(Process.pointerSize * 3).writePointer(bypassBuf);
          retval.replace(ptr(1));
        } catch (e) {}
      }
    });
    proxyFnsHooked['WinHttpGetIEProxyConfigForCurrentUser'] = true;
    console.log('[BurpMirage] Proxy Force hooked WinHttpGetIEProxyConfigForCurrentUser -> ' + proxy);
    return true;
  }

  function hookWinHttpDefaultProxy() {
    var mod = Process.findModuleByName('winhttp.dll');
    if (!mod) return false;
    var addr = resolveModExport(mod, 'WinHttpGetDefaultProxyConfiguration');
    if (addr === null) return false;
    if (proxyFnsHooked['WinHttpGetDefaultProxyConfiguration']) return true;
    var proxyBuf = Memory.allocUtf16String(proxy);
    var bypassBuf = Memory.allocUtf16String('localhost;127.*;<local>');
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.info = args[0];
      },
      onLeave: function (retval) {
        try {
          if (this.info.isNull()) return;
          // WINHTTP_PROXY_INFO { DWORD dwAccessType; LPWSTR lpszProxy; LPWSTR lpszProxyBypass; }
          this.info.writeU32(3); // NAMED_PROXY
          this.info.add(Process.pointerSize).writePointer(proxyBuf);
          this.info.add(Process.pointerSize * 2).writePointer(bypassBuf);
          retval.replace(ptr(1));
        } catch (e) {}
      }
    });
    proxyFnsHooked['WinHttpGetDefaultProxyConfiguration'] = true;
    console.log('[BurpMirage] Proxy Force hooked WinHttpGetDefaultProxyConfiguration -> ' + proxy);
    return true;
  }

  var ieProxy = false;
  var defProxy = false;
  try { ieProxy = hookWinHttpIeProxyConfig(); } catch (e) {}
  try { defProxy = hookWinHttpDefaultProxy(); } catch (e2) {}
  if (ieProxy || defProxy) hookedAny = true;

  // Late-load: when winhttp/wininet appear, install again.
  var loaders = ['LoadLibraryW', 'LoadLibraryExW', 'LoadLibraryA', 'LoadLibraryExA'];
  loaders.forEach(function (ln) {
    var k32 = Process.findModuleByName('kernel32.dll');
    if (!k32) return;
    var p = k32.findExportByName ? k32.findExportByName(ln) : null;
    if (p === null && typeof Module.findExportByName === 'function') {
      p = Module.findExportByName('kernel32.dll', ln);
    }
    if (p === null) return;
    Interceptor.attach(p, {
      onLeave: function (retval) {
        if (retval.isNull()) return;
        if (!proxyForceInstalled) return;
        try {
          hookWinHttpOpen('WinHttpOpen');
          hookInternetOpen('InternetOpenW', true);
          hookInternetOpen('InternetOpenA', false);
          hookWinHttpIeProxyConfig();
          hookWinHttpDefaultProxy();
        } catch (e) {}
      }
    });
  });

  proxyForceInstalled = true;
  send({
    type: 'event',
    message: 'Mode A Proxy Force ' + (hookedAny ? 'active' : 'armed (waiting for WinHTTP/WinInet)')
        + ' -> ' + proxy
        + ' ieProxyHook=' + ieProxy
        + ' defaultProxyHook=' + defProxy
        + ' (process-local only; does not change Windows system proxy)'
  });
}

function installSocketHooks() {
  if (socketHooksInstalled) {
    return;
  }
  if (getWs2() === null) {
    send({ type: 'event', message: 'ws2_32.dll not loaded yet in pid ' + Process.id + ' (Mode B pending)' });
    setTimeout(function () {
      if (modeSocketMirage && !socketHooksInstalled) {
        installSocketHooks();
      }
    }, 1000);
    return;
  }

  hookSendLike('send');
  hookSendLike('sendto');
  hookRecvLike('recv');
  hookRecvLike('recvfrom');

  var wsaSend = resolveExport('WSASend');
  if (wsaSend !== null) {
    Interceptor.attach(wsaSend, {
      onEnter: function (args) {
        if (!hooked.send) return;
        this.s = args[0].toInt32();
        lastSocketFd = this.s;
        noteSocketHandle(args[0]);
        var lpBuffers = args[1];
        var count = args[2].toInt32();
        if (count < 1) return;
        var len = wsabufLen(lpBuffers);
        var buf = wsabufPtr(lpBuffers);
        var decision = requestDecision('send', 'WSASend', this.s, buf, len);
        this.drop = decision && decision.action === 'drop';
        this.lpBuffers = lpBuffers;
        if (!this.drop && decision && decision.data) {
          var applied = applyInPlace(buf, len, decision);
          if (applied && !applied.drop) {
            lpBuffers.writeU32(applied.length);
          }
        }
      },
      onLeave: function (retval) {
        if (this.drop) {
          retval.replace(-1);
        }
      }
    });
    console.log('[BurpMirage] hooked WSASend');
  }

  hookWSARecv();
  trackSocketConstructors();
  installSocketFileIoHooks();
  socketHooksInstalled = true;
  send({ type: 'event', message: 'Mode B Winsock+WriteFile/ReadFile hooks installed in pid ' + Process.id });
}

function noteSocketHandle(h) {
  try {
    if (h === undefined || h === null) return;
    var key = (typeof h === 'object' && h.toString) ? h.toString() : ('' + h);
    if (key === '0' || key === '0x0') return;
    socketHandles[key] = true;
  } catch (e) {}
}

function isTrackedSocketHandle(h) {
  try {
    if (h === undefined || h === null) return false;
    var key = (typeof h === 'object' && h.toString) ? h.toString() : ('' + h);
    return !!socketHandles[key];
  } catch (e) {
    return false;
  }
}

/** Soft probe: treat HANDLE as SOCKET if getsockopt(SO_TYPE) succeeds (covers pre-attach sockets). */
function ensureSocketHandle(h) {
  if (isTrackedSocketHandle(h)) {
    return true;
  }
  try {
    var addr = resolveExport('getsockopt');
    if (addr === null) {
      return false;
    }
    if (!ensureSocketHandle._fn) {
      ensureSocketHandle._fn = new NativeFunction(addr, 'int', ['pointer', 'int', 'int', 'pointer', 'pointer']);
    }
    var optval = Memory.alloc(4);
    var optlen = Memory.alloc(4);
    optlen.writeS32(4);
    // SOL_SOCKET=0xffff, SO_TYPE=0x1008
    var rc = ensureSocketHandle._fn(h, 0xffff, 0x1008, optval, optlen);
    if (rc === 0) {
      noteSocketHandle(h);
      return true;
    }
  } catch (e) {}
  return false;
}

function trackSocketConstructors() {
  ['socket', 'WSASocketW', 'WSASocketA', 'accept', 'WSAAccept'].forEach(function (name) {
    var addr = resolveExport(name);
    if (addr === null) return;
    Interceptor.attach(addr, {
      onLeave: function (retval) {
        try {
          if (!retval.isNull && retval.isNull()) return;
          // INVALID_SOCKET is -1 / ~0
          var n = retval.toInt32();
          if (n === -1 || n === 0) return;
          noteSocketHandle(retval);
        } catch (e) {}
      }
    });
  });
}

/**
 * Chromium/Electron often bypasses send/WSASend and writes socket HANDLEs via WriteFile/ReadFile (IOCP).
 */
function installSocketFileIoHooks() {
  var k32 = Process.findModuleByName('kernel32.dll');
  if (!k32) return;

  function hookWrite(name) {
    var addr = resolveModExport(k32, name);
    if (addr === null) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        if (!hooked.send || suppressHook) {
          this.skip = true;
          return;
        }
        this.skip = false;
        this.h = args[0];
        if (!ensureSocketHandle(this.h)) {
          this.skip = true;
          return;
        }
        this.buf = args[1];
        this.len = args[2].toInt32();
        if (this.len <= 0) return;
        // Buffer is valid onEnter even for OVERLAPPED writes
        var fd = this.h.toInt32();
        lastSocketFd = fd;
        var decision = requestDecision('send', name, fd, this.buf, this.len);
        var applied = applyInPlace(this.buf, this.len, decision);
        this.drop = applied.drop;
        if (!this.drop && decision && decision.data) {
          args[2] = ptr(applied.length);
        }
      },
      onLeave: function (retval) {
        if (this.skip) return;
        if (this.drop) {
          retval.replace(ptr(0));
        }
      }
    });
    console.log('[BurpMirage] hooked ' + name + ' (socket handles)');
  }

  function hookRead(name) {
    var addr = resolveModExport(k32, name);
    if (addr === null) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.h = args[0];
        this.buf = args[1];
        this.lpRead = args[3];
        this.overlapped = args[4];
        this.async = this.overlapped && !this.overlapped.isNull();
        this.skip = !hooked.recv || !ensureSocketHandle(this.h);
        if (this.skip) {
          return;
        }
        lastSocketFd = this.h.toInt32();
        if (this.async) {
          try {
            pendingOverlappedReads[this.overlapped.toString()] = {
              h: this.h,
              buf: this.buf
            };
          } catch (e) {}
          this.skip = true; // completion via GetOverlappedResult / WSAGetOverlappedResult
        }
      },
      onLeave: function (retval) {
        if (this.skip) return;
        if (retval.toInt32() === 0) return;
        var got = 0;
        try {
          if (this.lpRead && !this.lpRead.isNull()) {
            got = this.lpRead.readU32();
          }
        } catch (e) {
          return;
        }
        if (got <= 0) return;
        var fd = this.h.toInt32();
        var decision = requestDecision('recv', name, fd, this.buf, got);
        var applied = applyInPlace(this.buf, got, decision);
        if (applied.drop) {
          try { this.lpRead.writeU32(0); } catch (e2) {}
          retval.replace(ptr(0));
        } else if (decision && decision.data) {
          try { this.lpRead.writeU32(applied.length); } catch (e3) {}
        }
      }
    });
    console.log('[BurpMirage] hooked ' + name + ' (socket handles)');
  }

  function finishOverlappedRead(apiName, hFile, lpOverlapped, lpTransferred, success) {
    if (!hooked.recv || !success || !lpOverlapped || lpOverlapped.isNull()) {
      return;
    }
    var key = lpOverlapped.toString();
    var pending = pendingOverlappedReads[key];
    if (!pending) {
      return;
    }
    delete pendingOverlappedReads[key];
    var got = 0;
    try {
      if (lpTransferred && !lpTransferred.isNull()) {
        got = lpTransferred.readU32();
      }
    } catch (e) {
      return;
    }
    if (got <= 0) {
      return;
    }
    var fd = pending.h.toInt32();
    lastSocketFd = fd;
    var decision = requestDecision('recv', apiName, fd, pending.buf, got);
    applyInPlace(pending.buf, got, decision);
  }

  function hookGetOverlappedResult(name, mod) {
    var addr = resolveModExport(mod, name);
    if (addr === null) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.h = args[0];
        this.ov = args[1];
        this.transferred = args[2];
      },
      onLeave: function (retval) {
        finishOverlappedRead(name, this.h, this.ov, this.transferred, retval.toInt32() !== 0);
      }
    });
    console.log('[BurpMirage] hooked ' + name + ' (overlapped read)');
  }

  hookWrite('WriteFile');
  hookWrite('WriteFileEx');
  hookRead('ReadFile');
  hookGetOverlappedResult('GetOverlappedResult', k32);
  var ws2 = getWs2();
  if (ws2) {
    hookGetOverlappedResult('WSAGetOverlappedResult', ws2);
  }
}

function install() {
  detectAndAnnounce();
  send({
    type: 'event',
    message: 'modes: proxyForce=' + modeProxyForce
        + ' socketMirage=' + modeSocketMirage
        + ' tlsUnpin=' + modeTlsUnpin
        + ' burpProxy=' + proxyString()
  });
  if (modeProxyForce) {
    installProxyForce();
  }
  if (modeSocketMirage) {
    installSocketHooks();
    try {
      installSslTrafficHooks();
    } catch (eSsl) {
      send({ type: 'event', message: 'Mode B SSL_io hook error: ' + eSsl });
    }
    // Chromium may load chrome.dll late — retry SSL hooks a few times.
    var sslRetries = 0;
    var sslTimer = setInterval(function () {
      sslRetries++;
      try {
        installSslTrafficHooks();
      } catch (e2) {}
      if (sslIoHookCount > 0 || sslRetries >= 15) {
        clearInterval(sslTimer);
      }
    }, 1000);
  }
  if (modeTlsUnpin) {
    installTlsUnpin();
  }
  if (!modeProxyForce && !modeSocketMirage && !modeTlsUnpin) {
    send({ type: 'event', message: 'WARNING: Mode A/B/C all OFF — nothing hooked' });
  }
}

setImmediate(install);
