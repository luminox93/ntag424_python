# NTAG 424 DNA Python Toolkit

## 🔄 프로젝트 전환 배경: 왜 Python인가?

이 프로젝트는 원래 Java(`javax.smartcardio`) 기반으로 시작되었으나, EV2 Secure Messaging 구현의 복잡성, PC/SC JNI 불안정성, 그리고 디버깅의 어려움으로 인해 **Python**으로 전환되었습니다.
Python의 `pyscard`와 `pycryptodome`을 활용하여, 복잡한 암호화 로직(AES-CMAC, IV Rotation)과 APDU 통신을 더 간결하고 직관적으로 구현하였습니다.

---

## 📂 프로젝트 구조

현재 프로젝트는 루트 경로의 `main.py`와 `ntag424.py`를 중심으로 동작합니다.

```text
F:\ntag424_python\
├── main.py          # 실행 진입점: 사용자 인터랙션, 태그 연결 및 시나리오 실행
├── ntag424.py       # 코어 드라이버: NTAG 424 DNA 명령어(EV2, ISO7816) 및 암호화 구현
├── tests/           # 패킷 구조 및 로직 검증 스크립트
│   ├── test_packet_structure.py # 패킷 구조 검증
│   └── verify_logic.py          # 암호화 로직 단위 테스트
├── docs/            # 데이터시트 및 문서
└── src/             # (참고용) 구조 개선을 위한 패키지 소스
```

## ✅ 현재 기능 (구현 현황)

*   **연결 (Connectivity)**: PC/SC 리더기를 통한 ISO 14443-4 연결.
*   **인증 (Authentication)**:
    *   `AuthenticateEV2First` (Cmd 0x71): AES-128 기반 인증 및 세션 키(Enc, Mac) 유도 완료.
*   **설정 변경 (Configuration)**:
    *   `ChangeFileSettings` (Cmd 0x5F): 통신 모드(Plain/Mac/Enc) 및 접근 권한(RW/Car) 설정.
    *   SDM(Secure Dynamic Messaging) 미러링 설정 (UID, Counter, CMAC).
*   **데이터 쓰기 (Data Writing)**:
    *   `WriteData` (Cmd 0x8D): Standard 모드에서 NDEF 데이터 기록.

---

## 🚀 개발 로드맵 & To-Do 체크리스트

### 1단계: 핵심 기능 구현 (Core) - *진행 중*
목표: 태그 인증 및 URL 미러링 설정 기능 완비.

- [x] **드라이버 기본**: APDU 송수신 및 세션 관리 (`ntag424.py`).
- [x] **암호화 모듈**: AES-CBC/ECB 암호화, CMAC 계산, 패딩(ISO7816) 처리.
- [x] **인증 로직**: `AuthenticateEV2First` (Key 0 사용) 구현.
- [x] **SDM 설정**: `ChangeFileSettings` 구현 (File 02 타겟).
- [x] **NDEF 쓰기**: `WriteData` 구현 (URI 레코드).
- [ ] **키 변경 (`ChangeKey`)**: 기본 키를 변경하는 기능 구현 필요.
- [ ] **UID 읽기**: `GetCardUID` 명령어 구현.

### 2단계: 안정성 및 검증 (Validation)
목표: 다양한 시나리오에서의 에러 처리 및 데이터 무결성 검증.

- [x] **패킷 구조 테스트**: `tests/test_packet_structure.py`를 통한 미러링 패킷 구조 검증.
- [ ] **로직 검증 스크립트**: `tests/verify_logic.py` 경로 수정 및 암호화 벡터 검증 자동화.
- [ ] **입력 값 검증**: URL 길이 및 오프셋 계산 시 경계값 테스트.
- [ ] **예외 처리**: 태그가 도중에 떨어지거나 인증 실패 시의 우아한 복구 처리.

### 3단계: 확장 및 배포 (Advanced)
목표: 보안 강화 및 사용자 편의 도구 제공.

- [ ] **LRP 모드 지원**: AES 외에 LRP(Leakage Resilient Primitive) 암호화 모드 추가.
- [ ] **배치 작업 (Batch Programming)**: 다수의 태그를 연속으로 설정하는 기능.
- [ ] **GUI 도입**: CLI 외에 PyQt 등을 활용한 데스크탑 앱.

---

## 🛠️ 다운로드 및 실행 방법

이 프로젝트를 로컬 컴퓨터에 다운로드받아 실행하는 방법입니다.

### 사전 준비 사항
*   **Python 3.8 이상**이 설치되어 있어야 합니다.
*   **PC/SC 호환 NFC 리더기** (예: ACR122U 등)가 컴퓨터에 연결되어 있어야 합니다.

### 1. 프로젝트 다운로드
Git을 사용하거나 ZIP 파일로 다운로드합니다.
```bash
git clone <repository_url>
cd ntag424_python
```

### 2. 가상 환경 생성 (권장)
파이썬 패키지 충돌을 방지하기 위해 가상 환경을 사용하는 것이 좋습니다.
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. 의존성 라이브러리 설치
필수 라이브러리(`pyscard`, `pycryptodome`)를 설치합니다.
```bash
pip install pyscard pycryptodome
```

### 4. 프로그램 실행
리더기에 NTAG 424 DNA 태그를 올려놓은 상태에서 아래 명령어를 실행합니다.
```bash
python main.py
```

### 5. 테스트 실행
패킷 구조가 올바른지 검증하려면 테스트 스크립트를 실행합니다.
```bash
python tests/test_packet_structure.py
```