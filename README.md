# BurpMirage

![Burp Suite](https://img.shields.io/badge/Burp_Suite-Montoya_API-FF6633?logo=burpsuite&logoColor=white)
![Frida](https://img.shields.io/badge/Frida-17%2B-8A2BE2?logo=frida&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)

> **Korean docs:** [README.ko.md](README.ko.md) · **Korean UI JAR:** [v1.0.0-ko](https://github.com/KaiHT-Ladiant/BurpMirage/releases/tag/v1.0.0-ko)
>
> **No Python needed:** grab the standalone bridge `burpmirage-bridge.exe` from [Releases](https://github.com/KaiHT-Ladiant/BurpMirage/releases) — it bundles Frida, so no `pip install` is required.

Burp Suite extension for intercepting, inspecting, and modifying **raw TCP / binary** traffic from arbitrary Windows processes — inspired by EchoMirage-style Winsock hooking.

Because Burp runs on the JVM and cannot inject DLLs directly, BurpMirage uses a **Frida hybrid**:

```
┌──────────────────────────────┐
│  Burp Suite (Java / Montoya) │
│  Process / Intercept / Hex   │
│  History / Repeater / Settings│
└──────────────┬───────────────┘
               │ TCP JSON-lines (127.0.0.1:27042)
┌──────────────▼───────────────┐
│  frida_bridge.py (Python)    │
└──────────────┬───────────────┘
               │ Frida IPC
┌──────────────▼───────────────┐
│  Target process              │
│  hooks.js → ws2_32 send/recv │
└──────────────────────────────┘
```

## Features

- **Process selector** — list running processes (name, PID, path) and **Inject & Hook**
- **Non-HTTP / binary protocols** — Hex dump editor with ASCII column
- **Live intercept** — Forward / Drop with in-place buffer patching
- **History** — Edited marker, Original vs Edited view, column sorting
- **Repeater** — reinject packets and pair the next RECV as a response (Request ID)
- **Settings** — bridge port, Python path auto-detect, hook toggles, file logging

## Requirements

| Component | Notes |
|-----------|--------|
| Burp Suite | Montoya API (recent Professional / Community) |
| JDK | **17+** (build) |
| Python | **Optional** — only if you don't use `burpmirage-bridge.exe`. 3.9+ with `frida` |
| OS | Windows |
| Privileges | Administrator may be required depending on the target |
| Architecture | 64-bit bridge attaches to both 32- and 64-bit targets |

Using the standalone `burpmirage-bridge.exe` (from Releases) requires **no Python**. If you prefer the Python bridge instead:

```bash
pip install frida frida-tools
```

## Build

```bash
./gradlew jarEn jarKo
```

Artifact: `build/libs/burpmirage-1.0.0-en.jar` (English UI) or `burpmirage-1.0.0-ko.jar` (Korean UI)

### Standalone bridge (no Python for end users)

The Frida host can be shipped as a single self-contained executable that **bundles Frida** — end users then need neither Python nor `pip install`.

```bash
packaging\build_bridge_exe.bat            REM uses "python" on PATH
packaging\build_bridge_exe.bat C:\path\to\python.exe
```

Output: `dist/burpmirage-bridge.exe`. The extension uses it automatically when it sits next to the JAR, or point **Settings → Bridge EXE path** at it. When no bridge exe is found, it falls back to a Python interpreter that has `frida`.

> Build the exe on the same OS/architecture you target (64-bit Windows recommended; a 64-bit Frida host can attach to both 32- and 64-bit processes).

### Load in Burp

1. **Extensions → Add → Java**
2. Select the JAR
3. Extension class: `com.burpmirage.burp.BurpMirageExtension`

## Quick start

1. Load the extension — suite tab **BurpMirage** appears; bridge listens on `127.0.0.1:27042`.
2. **Pick a bridge** (choose one):
   - **Recommended (no Python):** put `burpmirage-bridge.exe` next to the JAR, or set **Settings → Bridge EXE path** to it.
   - **Python:** set **Settings → Python path** to a `python.exe` that can `import frida` (or use **Detect Python+Frida**).
3. **Process Selector** — refresh, pick a process → **Inject & Hook**.
4. **Traffic Interceptor** — toggle Intercept ON, edit hex/ASCII, Forward or Drop.
5. Use **History** / **Repeater** for review and replay.

## Keyboard shortcuts (Traffic Interceptor)

Focus the Interceptor panel (e.g. click the hex dump), then:

| Shortcut | Action |
|----------|--------|
| **Ctrl+Shift+F** | Forward |
| **Ctrl+D** | Drop |

> **Note:** `Ctrl+F` is reserved by Burp and is **not** used for Forward.

## Tabs

| Tab | Purpose |
|-----|---------|
| Process Selector | Process list + Inject & Hook / Detach |
| Traffic Interceptor | Live intercept, hex edit, Forward / Drop |
| History | Packet log, Edited flag, Original/Edited view |
| Repeater | Hex-dump request editor + response capture |
| Settings | Bridge, Python, hooks, logging |

## Project layout

```
BurpMirage/
├── build.gradle.kts
├── settings.gradle.kts
├── README.md / README.ko.md
├── packaging/                    # PyInstaller build for burpmirage-bridge.exe
│   ├── burpmirage_bridge.spec
│   └── build_bridge_exe.bat
└── src/
    ├── i18n/                     # en/ko UI strings (bundled per JAR)
    └── main/
        ├── java/com/burpmirage/burp/
        │   ├── BurpMirageExtension.java
        │   ├── model/ intercept/ nativebridge/ ui/ util/
        └── resources/frida/
            ├── hooks.js
            └── frida_bridge.py
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Exit code **9009** | `python` not on PATH for Burp GUI — use `burpmirage-bridge.exe`, or set full `python.exe` path in Settings |
| `TypeError: not a function` in hooks | Old Frida 16 APIs — use Frida **17+** (current `hooks.js` is Frida 17 compatible) |
| Bridge `timed out` then host exits | Socket connect timeout left on the socket (fixed in recent builds) |
| No RECV / empty Repeater response | App may use async `WSARecv` (IOCP); sync `recv` / `WSARecv` are supported |
| Inject does nothing | No recent socket (`lastSocketFd`); generate traffic first, then Send |

## Limitations

- Overlapped / IOCP `WSARecv` coverage is limited.
- TLS plaintext is not decrypted (socket ciphertext/bytes only).
- In-place hooks cannot grow buffers beyond the original length.
- Protected / anti-cheat processes may block Frida attach.

## License / intended use

For security research and authorized testing on systems you own or have permission to analyze.
