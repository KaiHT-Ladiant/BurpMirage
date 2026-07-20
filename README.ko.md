# BurpMirage

![Burp Suite](https://img.shields.io/badge/Burp_Suite-Montoya_API-FF6633?logo=burpsuite&logoColor=white)
![Frida](https://img.shields.io/badge/Frida-17%2B-8A2BE2?logo=frida&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)

> **English docs:** [README.md](README.md) · **English UI JAR:** [v1.0.0-en](https://github.com/KaiHT-Ladiant/BurpMirage/releases/tag/v1.0.0-en)
>
> **Python 불필요:** [Releases](https://github.com/KaiHT-Ladiant/BurpMirage/releases)에서 단일 실행 브릿지 `burpmirage-bridge.exe`를 받으면 Frida가 내장되어 있어 `pip install` 없이 사용할 수 있습니다.

Windows 프로세스의 **raw TCP / 바이너리** 트래픽을 Burp Suite에서 가로채고, Hex로 보고, 수정·전달할 수 있는 Extension입니다. EchoMirage 스타일 Winsock 후킹을 목표로 합니다.

Burp는 JVM이라 DLL을 직접 주입할 수 없기 때문에 **Frida 하이브리드**로 구현했습니다.

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

## 기능

- **프로세스 선택** — 실행 중 프로세스 목록 + **주입 & 후킹**
- **비 HTTP / 바이너리 프로토콜** — Hex dump 편집기 (ASCII 컬럼)
- **실시간 인터셉트** — 전달 / 드롭, 버퍼 인플레이스 수정
- **히스토리** — 수정 표시, 원본/수정본 보기, 컬럼 정렬
- **리피터** — 패킷 재주입 + 다음 RECV를 응답으로 페어링 (Request ID)
- **설정** — 브릿지 포트, Python 자동 탐지, 후킹 토글, 파일 로깅

## 요구 사항

| 구성 요소 | 비고 |
|-----------|------|
| Burp Suite | Montoya API (최근 Professional / Community) |
| JDK | **17+** (빌드용) |
| Python | **선택** — `burpmirage-bridge.exe`를 쓰면 불필요. 안 쓸 경우 3.9+ (`frida`) |
| OS | Windows |
| 권한 | 대상에 따라 관리자 권한 필요 |
| 아키텍처 | 64비트 브릿지는 32/64비트 대상 모두 attach 가능 |

Releases의 단일 실행 `burpmirage-bridge.exe`를 쓰면 **Python이 필요 없습니다.** Python 브릿지를 직접 쓰려면:

```bash
pip install frida frida-tools
```

## 빌드

```bash
./gradlew jarEn jarKo
```

산출물:
- `build/libs/burpmirage-1.0.0-en.jar` — **영문 UI**
- `build/libs/burpmirage-1.0.0-ko.jar` — **한글 UI**

### 단일 실행 브릿지 (최종 사용자 Python 불필요)

Frida 호스트를 **Frida가 내장된 단일 실행 파일**로 패키징할 수 있습니다. 이 경우 사용자는 Python도, `pip install`도 필요 없습니다.

```bash
packaging\build_bridge_exe.bat            REM PATH의 "python" 사용
packaging\build_bridge_exe.bat C:\경로\python.exe
```

산출물: `dist/burpmirage-bridge.exe`. 이 exe를 JAR 옆에 두면 자동으로 사용되고, 또는 **설정 → 브릿지 EXE 경로**에 지정하면 됩니다. exe가 없으면 `frida`가 설치된 Python으로 폴백합니다.

> exe는 대상과 동일한 OS/아키텍처에서 빌드하세요 (64비트 Windows 권장; 64비트 Frida 호스트는 32/64비트 프로세스 모두 attach 가능).

### Burp에 로드

1. **Extensions → Add → Java**
2. JAR 선택 (한글 UI는 `-ko` 파일)
3. Extension class: `com.burpmirage.burp.BurpMirageExtension`

## 빠른 시작

1. Extension 로드 — **BurpMirage** 탭 생성, 브릿지 `127.0.0.1:27042` 수신
2. **브릿지 선택** (택 1):
   - **권장 (Python 불필요):** `burpmirage-bridge.exe`를 JAR 옆에 두거나 **설정 → 브릿지 EXE 경로**에 지정
   - **Python:** **설정 → Python 경로**에 `import frida` 가능한 `python.exe` 지정 (또는 **Python+Frida 탐지**)
3. **프로세스 선택** — 새로고침 → 프로세스 선택 → **주입 & 후킹**
4. **트래픽 인터셉터** — 인터셉트 ON, Hex/ASCII 수정, 전달 또는 드롭
5. **히스토리** / **리피터**로 검토·재전송

## 단축키 (트래픽 인터셉터)

인터셉터 패널에 포커스한 상태에서:

| 단축키 | 동작 |
|--------|------|
| **Ctrl+Shift+F** | 전달 (Forward) |
| **Ctrl+D** | 드롭 (Drop) |

> **참고:** `Ctrl+F`는 Burp가 사용하므로 Forward에 쓰지 않습니다.

## 탭

| 탭 | 용도 |
|----|------|
| 프로세스 선택 | 프로세스 목록 + 주입 & 후킹 / 분리 |
| 트래픽 인터셉터 | 실시간 인터셉트, Hex 편집, 전달 / 드롭 |
| 히스토리 | 패킷 로그, 수정 표시, 원본/수정본 보기 |
| 리피터 | Hex dump 요청 편집 + 응답 캡처 |
| 설정 | 브릿지, Python, 후킹, 로깅 |

## 트러블슈팅

| 증상 | 원인 |
|------|------|
| 종료 코드 **9009** | Burp GUI PATH에 `python` 없음 — `burpmirage-bridge.exe` 사용, 또는 설정에서 `python.exe` 전체 경로 지정 |
| hooks에서 `TypeError: not a function` | Frida 16 API — Frida **17+** 사용 |
| 브릿지 타임아웃 후 호스트 종료 | 소켓 connect timeout (최근 빌드에서 수정) |
| RECV 없음 / 리피터 응답 비어 있음 | 비동기 `WSARecv`(IOCP) 사용 가능 — 동기 `recv`/`WSARecv` 지원 |
| 주입 후 반응 없음 | 최근 소켓 없음 (`lastSocketFd`) — 트래픽 발생 후 Send |

## 제한 사항

- Overlapped / IOCP `WSARecv` 커버리지 제한
- TLS 평문 복호화 없음 (소켓 바이트만)
- 인플레이스 후킹은 원본 길이 초과 불가
- 보호/안티치트 프로세스는 Frida attach 차단 가능

## 라이선스 / 사용 목적

본인 소유 또는 분석 권한이 있는 시스템에 대한 보안 연구·허가된 테스트용입니다.
