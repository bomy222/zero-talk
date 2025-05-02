# chat_server.py

from flask import Flask, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

connected_users = {}
chat_logs = []

@socketio.on('connect')
    def handle_connect():
        print(f"클라이언트 접속: {request.sid}")

@socketio.on('disconnect')
    def handle_disconnect():
        user = None
        for k, v in connected_users.items():
            if v == request.sid:
                user = k
                break
        if user:
            del connected_users[user]
            print(f"{user} 접속 종료")

@socketio.on('register')
    def handle_register(data):
        username = data.get("username")
        if username:
            connected_users[username] = request.sid
            print(f"{username} 등록됨")
            emit('user_registered', {"message": "등록 완료"}, room=request.sid)

@socketio.on('send_message')
    def handle_send_message(data):
        sender = data.get("sender")
        receiver = data.get("receiver")
        message = data.get("message")
        timestamp = data.get("timestamp")
    
        print(f"{sender} -> {receiver}: {message}")
        chat_logs.append(data)

        if receiver in connected_users:
            emit('receive_message', data, room=connected_users[receiver])
        else:
            print(f"{receiver}는 현재 오프라인")

@socketio.on('get_user_list')
    def handle_get_user_list():
        emit('user_list', list(connected_users.keys()), room=request.sid)

@socketio.on('get_chat_logs')
    def handle_get_chat_logs():
        emit('chat_logs', chat_logs, room=request.sid)

@socketio.on('send_group_message')
    def handle_group_message(data):
        sender = data.get("sender")
        message = data.get("message")
        timestamp = data.get("timestamp")
        print(f"[단체방] {sender}: {message}")
        emit('group_message', {
            "sender": sender,
            "message": message,
            "timestamp": timestamp
            }, broadcast=True)

@socketio.on('ping')
    def handle_ping():
        emit('pong', {"status": "alive"})

@socketio.on('force_disconnect')
    def handle_force_disconnect(data):
        target = data.get("username")
        if target in connected_users:
            emit('force_exit', {}, room=connected_users[target])
            del connected_users[target]
            print(f"{target} 강제 종료됨")

@socketio.on('join_room')
    def handle_join_room(data):
        room = data.get("room")
        username = data.get("username")
        if room and username:
            emit("system", f"{username} 님이 {room}에 입장했습니다.", broadcast=True)

@socketio.on('leave_room')
    def handle_leave_room(data):
        room = data.get("room")
        username = data.get("username")
        if room and username:
            emit("system", f"{username} 님이 {room}을 나갔습니다.", broadcast=True)

if __name__ == '__main__':
    print("ZeroTalk Chat Server 실행 중... http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000)