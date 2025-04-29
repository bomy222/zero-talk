# ZeroTalk

**ZeroTalk**는 안전하고 직관적인 사용자 인증 시스템을 제공하는 Flask 기반 데스크탑 메신저 프로젝트입니다.  
SocketIO를 통해 실시간 양방향 통신이 가능하며, 사용자 로그인 정보는 JSON 파일로 안전하게 관리됩니다.

---

## 주요 기능

- 사용자 로그인 (ID, 비밀번호 입력)
- 로그인 성공 시 메인 화면 진입
- 사용자 정보는 `user_data.json`에 저장
- 실시간 기능 연동 가능 (Flask-SocketIO 기반)

---

## 폴더 구조

zerotalk-env/ │ 
├── templates/ │   ├── login.py │   └── main_screen.py │ 
├── app.py 
├── user_data.json 
├── zerotalk_main.py 
├── zerotalk_logs.json 
└── .gitignore