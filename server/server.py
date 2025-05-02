import socketio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# FastAPI 앱과 Socket.IO 서버 구성
app = FastAPI()
sio = socketio.AsyncServer(cors_allowed_origins="*")
sio_app = socketio.ASGIApp(sio, other_asgi_app=app)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 유저 상태 추적
connected_users = {}

# 단톡방 관리
rooms = {
    "public": []  # 기본 공개 채팅방
    }

@app.get("/")
async def read_root():
    return {"status": "ZeroTalk SocketIO 서버 실행 중"}

# 유저 연결 처리
@sio.event
async def connect(sid, environ):
    print(f"[접속] 새 유저 세션: {sid}")

@sio.event
async def disconnect(sid):
    user = connected_users.pop(sid, None)
    print(f"[종료] 세션: {sid}, 사용자: {user}")
    if user:
        await sio.emit("user_left", {"user": user}, skip_sid=sid)

# 유저 로그인 (닉네임 등록)
@sio.event
async def register(sid, data):
    username = data.get("username")
    if username:
        connected_users[sid] = username
        print(f"[로그인] {username} ({sid})")
        await sio.emit("user_joined", {"user": username}, skip_sid=sid)

# 1:1 메시지 처리
@sio.event
async def send_message(sid, data):
    sender = data.get("sender")
    receiver = data.get("receiver")
    message = data.get("message")
    timestamp = data.get("timestamp")

    print(f"[메시지] {sender} → {receiver} | {message}")
    
    for s, u in connected_users.items():
        if u == receiver:
            await sio.emit("receive_message", {
                "sender": sender,
                "message": message,
                "timestamp": timestamp
            }, to=s)
            break

# 단체방 메시지 처리
@sio.event
async def send_group_message(sid, data):
    sender = data.get("sender")
    room = data.get("room", "public")
    message = data.get("message")
    timestamp = data.get("timestamp")

    print(f"[단톡방:{room}] {sender}: {message}")

    await sio.emit("group_message", {
        "sender": sender,
        "message": message,
        "timestamp": timestamp,
        "room": room
    }, room=room)

# 단톡방 참가 요청
@sio.event
async def join_room(sid, data):
    room = data.get("room")
    username = connected_users.get(sid)
    if room and username:
        await sio.enter_room(sid, room)
        print(f"[참가] {username} → 방: {room}")
        await sio.emit("system", {
            "message": f"{username}님이 '{room}' 방에 참가하였습니다."
        }, room=room)

# 단톡방 나가기
@sio.event
async def leave_room(sid, data):
    room = data.get("room")
    username = connected_users.get(sid)
    if room and username:
        await sio.leave_room(sid, room)
        print(f"[퇴장] {username} → 방: {room}")
        await sio.emit("system", {
            "message": f"{username}님이 '{room}' 방에서 퇴장하였습니다."
        }, room=room)

# 서버 실행
if __name__ == "__main__":
    uvicorn.run(sio_app, host="0.0.0.0", port=5000)