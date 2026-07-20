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

function requestDecision(direction, api, fd, buf, length) {
  var id = nextId();
  var bytes = readBytes(buf, length);
  var payload = {
    type: 'packet',
    id: id,
    direction: direction,
    api: api,
    peer: peerOf(fd | 0),
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
  recv(id, function (value) {
    if (value) {
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
    return true;
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

function install() {
  if (getWs2() === null) {
    send({ type: 'event', message: 'ws2_32.dll not loaded yet in pid ' + Process.id });
    setTimeout(install, 1000);
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
          // Reflect logical length in WSABUF.len (same as send/sendto args[2]).
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

  send({ type: 'event', message: 'Winsock hooks installed in pid ' + Process.id });
}

setImmediate(install);
