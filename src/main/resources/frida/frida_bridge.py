#!/usr/bin/env python3
"""
Frida host bridge for Burp BurpMirage (Frida 17+).

Critical: never block Frida's on_message thread waiting for Burp.
Packet decisions are handled on worker threads; Interceptor recv().wait()
is unblocked via script.post() after Burp replies.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, Optional

# Unbuffered logs when spawned from Burp
os.environ.setdefault("PYTHONUNBUFFERED", "1")
try:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
except Exception:
    pass

try:
    import frida
except ImportError:
    print(
        "ERROR: frida Python package not found. Install with: pip install frida frida-tools",
        file=sys.stderr,
    )
    sys.exit(2)


class BurpBridge:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._pending_cv = threading.Condition()
        self._inject_handler = None
        self._config_handler = None
        self.alive = False

    def connect(self, retries: int = 40) -> None:
        last_err: Optional[Exception] = None
        for _ in range(retries):
            try:
                s = socket.create_connection((self.host, self.port), timeout=2.0)
                # create_connection() leaves the timeout on the socket — that makes
                # later recv() raise after idle periods and kill the Frida host.
                s.settimeout(None)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # Keepalive so middleboxes / idle disconnects are less likely
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock = s
                self.alive = True
                t = threading.Thread(target=self._read_loop, name="burp-bridge-reader", daemon=True)
                t.start()
                print(f"[*] Connected to Burp bridge {self.host}:{self.port}", flush=True)
                return
            except OSError as e:
                last_err = e
                time.sleep(0.25)
        raise RuntimeError(f"Could not connect to Burp bridge: {last_err}")

    def send_hello(self, pid: int) -> None:
        self._write({"type": "hello", "pid": pid})

    def send_event(self, message: str) -> None:
        self._write({"type": "event", "message": message})

    def request_decision(self, packet: Dict[str, Any], timeout: float = 120.0) -> Dict[str, Any]:
        packet_id = packet["id"]
        data_bytes = bytes(packet.get("data") or [])
        with self._pending_cv:
            self._pending[packet_id] = {}

        wire = {
            "type": "packet",
            "id": packet_id,
            "pid": packet.get("pid") or 0,
            "direction": packet.get("direction") or "send",
            "api": packet.get("api") or "",
            "peer": packet.get("peer") or "",
            "fd": packet.get("fd") or -1,
            "data": base64.b64encode(data_bytes).decode("ascii"),
        }
        self._write(wire)

        deadline = time.time() + timeout
        with self._pending_cv:
            while packet_id in self._pending and "action" not in self._pending[packet_id]:
                remaining = deadline - time.time()
                if remaining <= 0:
                    self._pending.pop(packet_id, None)
                    print(f"[!] Decision timeout for {packet_id} — auto-forward", flush=True)
                    return {"action": "forward", "data": list(data_bytes)}
                self._pending_cv.wait(timeout=min(remaining, 1.0))
            result = self._pending.pop(
                packet_id, {"action": "forward", "data": list(data_bytes)}
            )
        return result

    def _write(self, obj: Dict[str, Any]) -> None:
        if not self.sock:
            return
        line = json.dumps(obj, ensure_ascii=True) + "\n"
        with self._lock:
            try:
                self.sock.sendall(line.encode("utf-8"))
            except OSError as e:
                print(f"[!] Bridge write failed: {e}", file=sys.stderr, flush=True)
                self.alive = False

    def _read_loop(self) -> None:
        assert self.sock is not None
        buf = b""
        while self.alive:
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                # Should not happen with settimeout(None); keep going if it does.
                continue
            except socket.timeout:
                continue
            except OSError as e:
                # Ignore pure timeout-style errors; only stop on hard disconnects.
                msg = str(e).lower()
                if "timed out" in msg or "timeout" in msg:
                    continue
                print(f"[!] Bridge recv error: {e}", flush=True)
                break
            if not chunk:
                print("[!] Bridge peer closed connection", flush=True)
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                try:
                    self._handle_server_message(msg)
                except Exception as e:
                    print(f"[!] Server message handler error: {e}", flush=True)
        self.alive = False
        print("[*] Bridge reader stopped", flush=True)

    def _handle_server_message(self, msg: Dict[str, Any]) -> None:
        mtype = msg.get("type")
        if mtype == "inject":
            if self._inject_handler:
                raw = base64.b64decode(msg.get("data") or "")
                self._inject_handler(
                    list(raw),
                    msg.get("peer") or "",
                    bool(msg.get("waitResponse", True)),
                    msg.get("requestId") or "",
                )
            return
        if mtype == "config":
            if self._config_handler:
                self._config_handler(msg)
            return
        if mtype == "ping":
            self._write({"type": "pong", "ts": msg.get("ts")})
            return

        packet_id = msg.get("id")
        if not packet_id:
            return
        action = msg.get("action") or "forward"
        data_b64 = msg.get("data") or ""
        try:
            data = list(base64.b64decode(data_b64)) if data_b64 else None
        except Exception:
            data = None
        with self._pending_cv:
            if packet_id in self._pending:
                self._pending[packet_id] = {"action": action, "data": data}
                self._pending_cv.notify_all()

    def on_inject(self, handler) -> None:
        self._inject_handler = handler

    def on_config(self, handler) -> None:
        self._config_handler = handler

    def close(self) -> None:
        self.alive = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def _bundled_hooks_path() -> Optional[str]:
    """When frozen by PyInstaller, hooks.js is shipped alongside the binary."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = os.path.join(base, "hooks.js")
        if os.path.isfile(candidate):
            return candidate
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "hooks.js")
    return candidate if os.path.isfile(candidate) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="BurpMirage Frida ↔ Burp bridge")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27042)
    parser.add_argument(
        "--script",
        default=None,
        help="Path to hooks.js (optional; uses bundled copy when omitted)",
    )
    args = parser.parse_args()

    script_path = args.script or _bundled_hooks_path()
    if not script_path or not os.path.isfile(script_path):
        print(
            "ERROR: hooks.js not found. Pass --script <path> or ship hooks.js "
            "next to the executable.",
            file=sys.stderr,
        )
        return 5

    with open(script_path, "r", encoding="utf-8") as f:
        source = f.read()

    bridge = BurpBridge(args.host, args.port)
    bridge.connect()
    bridge.send_hello(args.pid)

    print(f"[*] Attaching to PID {args.pid}…", flush=True)
    try:
        session = frida.attach(args.pid)
    except Exception as e:
        print(f"[!] frida.attach failed: {e}", flush=True)
        bridge.close()
        return 3

    script = session.create_script(source)

    def handle_packet(payload: Dict[str, Any]) -> None:
        """Runs on a worker thread — must not run on Frida's message pump."""
        try:
            payload["pid"] = args.pid
            decision = bridge.request_decision(payload)
            script.post({"type": payload["id"], "payload": decision})
        except Exception as e:
            print(f"[!] packet worker error: {e}", flush=True)
            try:
                script.post(
                    {
                        "type": payload.get("id") or "unknown",
                        "payload": {"action": "forward", "data": payload.get("data")},
                    }
                )
            except Exception:
                pass

    def on_message(message: Dict[str, Any], data: Any) -> None:
        if message.get("type") == "error":
            print(f"[Frida error] {message}", file=sys.stderr, flush=True)
            bridge.send_event(f"error: {message.get('description')}")
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        ptype = payload.get("type")
        if ptype == "event":
            print(f"[event] {payload.get('message')}", flush=True)
            bridge.send_event(str(payload.get("message") or ""))
            return
        if ptype == "repeater_response":
            data_bytes = bytes(payload.get("data") or [])
            bridge._write(
                {
                    "type": "repeater_response",
                    "requestId": payload.get("requestId") or "",
                    "peer": payload.get("peer") or "",
                    "fd": payload.get("fd") or -1,
                    "data": base64.b64encode(data_bytes).decode("ascii"),
                }
            )
            return
        if ptype == "packet":
            # CRITICAL: do not block Frida's message thread on Burp I/O
            threading.Thread(
                target=handle_packet,
                args=(payload,),
                name=f"packet-{payload.get('id')}",
                daemon=True,
            ).start()
            return

    script.on("message", on_message)

    def handle_inject(
        byte_list, peer: str, wait_response: bool = True, request_id: str = ""
    ) -> None:
        try:
            rc = script.exports_sync.inject(byte_list, peer, wait_response, request_id)
            bridge.send_event(
                f"inject result={rc} ({len(byte_list)} bytes) "
                f"waitResponse={wait_response} requestId={request_id}"
            )
        except TypeError:
            try:
                rc = script.exports_sync.inject(byte_list, peer, wait_response)
                bridge.send_event(f"inject result={rc} ({len(byte_list)} bytes)")
            except TypeError:
                try:
                    rc = script.exports_sync.inject(byte_list, peer)
                    bridge.send_event(f"inject result={rc} ({len(byte_list)} bytes)")
                except Exception as e:
                    bridge.send_event(f"inject failed: {e}")
            except Exception as e:
                bridge.send_event(f"inject failed: {e}")
        except Exception as e:
            bridge.send_event(f"inject failed: {e}")

    def handle_config(cfg: Dict[str, Any]) -> None:
        try:
            script.exports_sync.configure(
                {
                    "hookSend": bool(cfg.get("hookSend", True)),
                    "hookRecv": bool(cfg.get("hookRecv", True)),
                }
            )
        except Exception as e:
            bridge.send_event(f"config failed: {e}")

    bridge.on_inject(handle_inject)
    bridge.on_config(handle_config)

    try:
        script.load()
    except Exception as e:
        print(f"[!] script.load failed: {e}", flush=True)
        bridge.close()
        return 4

    bridge.send_event(f"attached to pid {args.pid}")
    print(f"[*] Hooked PID {args.pid}. Waiting for traffic…", flush=True)

    exit_reason = "unknown"
    try:
        while True:
            if not bridge.alive:
                exit_reason = "bridge_disconnected"
                print("[!] Exit reason: Burp bridge disconnected", flush=True)
                # Try to keep Frida session for a moment (diagnostics), then leave
                break
            try:
                detached = session.is_detached
            except Exception as e:
                exit_reason = f"session_check_error:{e}"
                print(f"[!] Exit reason: {exit_reason}", flush=True)
                break
            if detached:
                exit_reason = "session_detached"
                print("[!] Exit reason: Frida session detached (target quit or agent died)", flush=True)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        exit_reason = "keyboard"
        print("[*] Detaching (KeyboardInterrupt)…", flush=True)
    finally:
        print(f"[*] Cleaning up (reason={exit_reason})", flush=True)
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        bridge.close()

    return 0 if exit_reason in ("keyboard", "bridge_disconnected", "session_detached") else 1


if __name__ == "__main__":
    sys.exit(main())
