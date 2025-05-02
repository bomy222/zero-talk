# ========================== 기본 내장 모듈 ==========================
import os
import time
import json
import base64
import shutil
import threading

# ========================== 외부 라이브러리 ==========================
from flask import Flask, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

app = Flask(__name__)
# 초기 설정 추가
LOG_DIR = "logs"
BACKUP_DIR = os.path.join(LOG_DIR, "backup")

# 디렉토리 존재하지 않으면 생성
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=30, ping_interval=10)

# 전역 저장소
connected_users = {}       # username: sid
room_members = {}          # room: [username]
chat_logs = []             # 단일 메시지 기록
room_logs = {}             # room: [{msg_dict}, ...]

# 파일 경로
CHAT_LOG_PATH = "logs/chat_logs.json"
ROOM_LOG_PATH = "logs/room_logs.json"

# ✅ 백업 폴더 경로 정의 및 폴더 생성
BACKUP_DIR = "logs/backup"
os.makedirs(BACKUP_DIR, exist_ok=True
            
# 유틸: 파일 로드/저장
    def save_json(path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def load_json(path):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return {}
        return {}

# 서버 부팅 시 채팅기록 불러오기
if os.path.exists(CHAT_LOG_PATH):
    chat_logs = load_json(CHAT_LOG_PATH)
if os.path.exists(ROOM_LOG_PATH):
    room_logs = load_json(ROOM_LOG_PATH)

# 연결 이벤트
@socketio.on('connect')
    def handle_connect():
        print(f"[접속] {request.sid}")

@socketio.on('disconnect')
    def handle_disconnect():
        disconnected_user = None
        for user, sid in connected_users.items():
            if sid == request.sid:
                disconnected_user = user
                break
        if disconnected_user:
            del connected_users[disconnected_user]
            print(f"[종료] {disconnected_user} 연결 해제됨")

# 사용자 등록
@socketio.on('register')
    def handle_register(data):
        username = data.get("username")
        if not username:
            return
        connected_users[username] = request.sid
        print(f"[등록] 사용자 {username} 등록됨")
        emit("user_registered", {"message": "등록 완료"}, room=request.sid)

# 개인 메시지 처리
@socketio.on('send_message')
    def handle_send_message(data):
        sender = data.get("sender")
        receiver = data.get("receiver")
        message = data.get("message")
        timestamp = data.get("timestamp", datetime.now().strftime("%H:%M:%S"))

        print(f"[DM] {sender} -> {receiver}: {message}")
        chat_logs.append(data)
        save_json(CHAT_LOG_PATH, chat_logs)

        if receiver in connected_users:
            emit("receive_message", data, room=connected_users[receiver])
        else:
            print(f"[오프라인] {receiver}는 현재 연결되어 있지 않음")

# 단톡방 생성
@socketio.on('create_room')
    def handle_create_room(data):
        room = data.get("room")
        creator = data.get("username")
        if room and room not in room_members:
            room_members[room] = [creator]
            room_logs[room] = []
            print(f"[방 생성] {room} by {creator}")
            emit("room_created", {"room": room}, broadcast=True)

# 단톡방 참여
@socketio.on('join_room')
    def handle_join_room(data):
        room = data.get("room")
        username = data.get("username")
        if room in room_members and username not in room_members[room]:
            room_members[room].append(username)
        join_room(room)
        emit("system", f"{username}님이 {room}에 입장했습니다.", room=room)

# 단톡방 메시지
@socketio.on("send_room_message")
    def handle_send_room_message(data):
        sender = data.get("sender")
        room = data.get("room")
        message = data.get("message")
        timestamp = data.get("timestamp", datetime.now().strftime("%H:%M:%S"))

        msg_data = {
            "sender": sender,
            "message": message,
            "timestamp": timestamp,
            "room": room
            }

    if room in room_logs:
        room_logs[room].append(msg_data)
        save_json(ROOM_LOG_PATH, room_logs)

    emit("receive_message", msg_data, room=room)

# 단톡방 퇴장
@socketio.on('leave_room')
    def handle_leave_room(data):
        room = data.get("room")
        username = data.get("username")
        if room in room_members and username in room_members[room]:
            room_members[room].remove(username)
    leave_room(room)
    emit("system", f"{username}님이 {room}을 떠났습니다.", room=room)

# 유저 리스트
@socketio.on('get_user_list')
    def handle_get_user_list():
        emit('user_list', list(connected_users.keys()), room=request.sid)

# 채팅 전체 로그 요청
@socketio.on('get_chat_logs')
    def handle_get_chat_logs():
        emit("chat_logs", chat_logs, room=request.sid)

# 방 로그 요청
@socketio.on("get_room_logs")
    def handle_get_room_logs(data):
        room = data.get("room")
        if room in room_logs:
            emit("room_logs", room_logs[room], room=request.sid)

# 상태 확인
@socketio.on("ping")
    def handle_ping():
        emit("pong", {"status": "alive"})

        if __name__ == "__main__":
            print(">> ZeroTalk 서버 시작됨: http://localhost:5000")
            socketio.run(app, host="0.0.0.0", port=5000)

 # ------------------- 보안: 토큰 기반 인증 -------------------
@socketio.on("token_auth")
    def handle_token_auth(data):
        username = data.get("username")
        token = data.get("token")
        if not username or not token:
            emit("token_status", {"status": "error", "message": "토큰 정보 누락"})
            return

        token_data = load_json("token_data.json")
            if token_data.get(username) == token:
                emit("token_status", {"status": "success", "message": "토큰 인증 완료"})
        else:
            emit("token_status", {"status": "fail", "message": "토큰 인증 실패"})

# ------------------- IP 제한 체크 -------------------
@socketio.on("check_ip")
    def handle_check_ip(data):
        ip = request.remote_addr
        ip_data = load_json("security_data.json")
        attempts = ip_data.get(ip, {"count": 0, "last": ""})
    
        if attempts["count"] >= 3:
            emit("ip_blocked", {"status": "blocked", "until": attempts["last"]})
            return
    
        emit("ip_status", {"status": "ok"})

# ------------------- 워키토키 기능 (음성 메시지 구조 설계) -------------------
@socketio.on("send_voice")
    def handle_send_voice(data):
        """
        data = {
            "sender": "user1",
            "receiver": "user2",
            "voice_chunk": "base64_encoded_string",
            "timestamp": "2025-05-02 21:30:00"
            
        """
        receiver = data.get("receiver")
        if receiver in connected_users:
            emit("receive_voice", data, room=connected_users[receiver])
            print(f"[음성 전송] {data['sender']} → {receiver}")
        else:
            print(f"[음성 실패] {receiver} 접속 안 됨")

@socketio.on("send_room_voice")
    def handle_send_room_voice(data):
        room = data.get("room")
        emit("receive_voice", data, room=room)
        print(f"[단톡 음성] {data['sender']} → {room}")

# ------------------- 시스템 상태 + 로깅 -------------------
@socketio.on("system_status")
    def handle_system_status():
        user_count = len(connected_users)
        room_count = len(room_members)
        log_count = len(chat_logs)
        emit("status_info", {
            "users_online": user_count,
            "rooms_active": room_count,
            "total_chats": log_count
            })

# ------------------- 관리자용: 전체 유저 브로드캐스트 -------------------
@socketio.on("admin_broadcast")
    def handle_admin_broadcast(data):
        msg = data.get("message")
        emit("admin_notice", {"message": msg}, broadcast=True)
        print(f"[공지] {msg}")

# ------------------- 강제 로그아웃 처리 -------------------
@socketio.on("force_logout")
    def handle_force_logout(data):
        target = data.get("target")
        if target in connected_users:
            emit("force_exit", {}, room=connected_users[target])
            print(f"[강제종료] {target} 연결 해제")
            del connected_users[target]

# ------------------- 단일방향 푸시 메시지 -------------------
@socketio.on("push_notify")
    def handle_push_notify(data):
        """
        {"target": "username", "title": "업데이트", "body": "신규 버전 배포됨"}
        """
        target = data.get("target")
        if target in connected_users:
            emit("push", data, room=connected_users[target])
            print(f"[PUSH] {data['title']} → {target}")

# ------------------- ping / pong for health check -------------------
@socketio.on("check_alive")
    def check_alive():
        emit("alive", {"status": "ok", "timestamp": time.time()})

# ========================================================================
# ✅ 채널 메시지 연동: 예) BomiDrive → ZeroTalk 채널 연동 구조
# ========================================================================
@socketio.on("channel_message")
    def handle_channel_message(data):
        channel = data.get("channel")          # 예: 'bomidrive'
        sender = data.get("sender")            # 예: 차량번호 또는 담당자
        message = data.get("message")          # 예: 정비 결과, 위치 등
        timestamp = data.get("timestamp") or datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        msg = {
            "sender": f"[{channel}] {sender}",
            "message": message,
            "timestamp": timestamp
            }

    # ZeroTalk 내부 시스템 채널에 전송 (예: 보미코인 채널 / 보미드라이브 채널)
        emit("channel_broadcast", msg, broadcast=True)
        print(f"[채널 {channel}] {sender} → {message}")

# ========================================================================
# ✅ 비상 메시지 수신 전용: 워키토키 기능 (단방향 수신 or 양방향)
# ========================================================================
@socketio.on("emergency_ping")
    def handle_emergency_ping(data):
        sender = data.get("sender")
        location = data.get("location") or "위치 미확인"
        reason = data.get("reason") or "사유 없음"
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        alert = {
            "type": "emergency",
            "sender": sender,
            "location": location,
            "reason": reason,
            "timestamp": timestamp
        }

    # 전체 운영자에게 비상 알림 전송
    emit("emergency_alert", alert, broadcast=True)
    print(f"[EMERGENCY] {sender} → {reason} @ {location}")

# ========================================================================
# ✅ 서버 로깅: 접속 현황 및 채팅 로그 주기적 저장용 타이머 예시
# ========================================================================
   
    def auto_save_logs(interval=300):
        def job():
            while True:
                save_json(CHAT_LOG_PATH, chat_logs)
                save_json(ROOM_LOG_PATH, room_logs)

                # 백업 파일명에 시간 붙이기
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                chat_backup = os.path.join(BACKUP_DIR, f"chat_{timestamp}.json")
                room_backup = os.path.join(BACKUP_DIR, f"room_{timestamp}.json")

                shutil.copy2(CHAT_LOG_PATH, chat_backup)
                shutil.copy2(ROOM_LOG_PATH, room_backup)

                print(f"[AUTO SAVE] 로그 저장 및 백업 완료: {timestamp}")
                time.sleep(interval)

        threading.Thread(target=job, daemon=True).start()

# 자동 저장 시작 (5분마다)
auto_save_logs(300) 

# ========================================================================
# ✅ 서버 시작
# ========================================================================
from admin import start_admin_monitor
start_admin_monitor()
if __name__ == "__main__":
    print(">> ZeroTalk 서버 최종 기동 시작: http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000)