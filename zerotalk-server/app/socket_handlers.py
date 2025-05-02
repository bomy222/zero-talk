import time
import socketio
import hashlib
import base64
import json
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                          # sid → user_id
chat_chain = defaultdict(list)                # room_id → [messages]
user_pubkeys = {}                             # user_id → RSA public key
chain_hashes = {}                             # room_id → 최종 해시

# SocketIO 서버 객체 생성
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

# 사용자 접속 상태 및 채팅 로그 저장소
connected_users = {}  # sid → {"user_id": "alice"}
chat_logs = defaultdict(list)  # user_id → 메시지 리스트

# 클라이언트 접속 시 호출
@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] 세션 ID: {sid}")

# 클라이언트 접속 종료 시 호출
@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

# 로그인 이벤트 처리
@sio.on("login")
    def handle_login(sid, data):
        user_id = data.get("user_id")
        connected_users[sid]["user_id"] = user_id
        print(f"[로그인] {user_id} ({sid})")
    # 시스템 메시지 브로드캐스트 (본인 제외)
sio.emit("system", {"message": f"{user_id}님이 입장하셨습니다."}, skip_sid=sid)

# 일반 메시지 수신 처리
@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        receiver = data.get("receiver")
        text = data.get("text", "")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        message = {
            "type": "text",
            "sender": sender,
            "receiver": receiver,
            "text": text,
            "timestamp": timestamp
        }

    # 채팅 로그 저장 및 메시지 전송
    chat_logs[receiver].append(message)
    sio.emit("message", message, room=receiver)

    print(f"[메시지] {sender} → {receiver} : {text}")

# 서버 실행
    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 1차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

# 서버 객체 생성
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

# 사용자 상태, 채팅 로그
connected_users = {}
chat_logs = defaultdict(list)

# 접속
@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

# 퇴장
@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

# 로그인
@sio.on("login")
    def handle_login(sid, data):
        user_id = data.get("user_id")
        connected_users[sid]["user_id"] = user_id
        print(f"[로그인] {user_id} ({sid})")
        sio.emit("system", {"message": f"{user_id}님이 입장하셨습니다."}, skip_sid=sid)

# 일반 메시지 + 송금 메시지 처리
@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        receiver = data.get("receiver")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_type == "text":
            text = data.get("text", "")
            message = {
                "type": "text",
                "sender": sender,
                "receiver": receiver,
                "text": text,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[메시지] {sender} → {receiver} : {text}")

        elif msg_type == "transfer":
            amount = data.get("amount")
            coin = data.get("coin", "USDT")
            memo = data.get("memo", "")

        # TX 해시 생성
        tx_base = f"{sender}|{receiver}|{amount}|{coin}|{time.time()}"
        tx_hash = hashlib.sha256(tx_base.encode()).hexdigest()[:20]

        tx_message = {
            "type": "transfer",
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "coin": coin,
            "memo": memo,
            "tx_id": tx_hash,
            "timestamp": timestamp
        }
        chat_logs[receiver].append(tx_message)
        sio.emit("message", tx_message, room=receiver)
        print(f"[송금] {sender} → {receiver} : {amount} {coin} (TX: {tx_hash})")

# 서버 실행
    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 2차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

# 개인 키 생성 (설치형에서는 파일로 보관 가능)
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.get_verifying_key()

# 서명
    def sign_tx(tx_id: str) -> str:
        return private_key.sign(tx_id.encode()).hex()

# 검증
    def verify_signature(tx_id: str, signature_hex: str) -> bool:
        try:
            signature = bytes.fromhex(signature_hex)
            return public_key.verify(signature, tx_id.encode())
        except:
            return False
        
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

@sio.on("login")
    def handle_login(sid, data):
        user_id = data.get("user_id")
        connected_users[sid]["user_id"] = user_id
        print(f"[로그인] {user_id} ({sid})")
        sio.emit("system", {"message": f"{user_id}님이 입장하셨습니다."}, skip_sid=sid)

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        receiver = data.get("receiver")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_type == "text":
            text = data.get("text", "")
            message = {
                "type": "text",
                "sender": sender,
                "receiver": receiver,
                "text": text,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[메시지] {sender} → {receiver} : {text}")

        elif msg_type == "transfer":
            amount = data.get("amount")
            coin = data.get("coin", "USDT")
            memo = data.get("memo", "")

        # TX 해시 생성
        tx_base = f"{sender}|{receiver}|{amount}|{coin}|{time.time()}"
        tx_id = hashlib.sha256(tx_base.encode()).hexdigest()[:20]
        signature = sign_tx(tx_id)

        tx_message = {
            "type": "transfer",
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "coin": coin,
            "memo": memo,
            "tx_id": tx_id,
            "signature": signature,
            "timestamp": timestamp
            }

        chat_logs[receiver].append(tx_message)
        sio.emit("message", tx_message, room=receiver)
        print(f"[송금] {sender} → {receiver} : {amount} {coin} (TX: {tx_id})")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 3차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

# 고정 키 (테스트용), 실제 환경에서는 사용자마다 다르게

SECRET_KEY = hashlib.sha256(b"zerotalk-secret-key").digest()

    def encrypt_message(plaintext: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode()
        ct = base64.b64encode(ct_bytes).decode()
        return f"{iv}:{ct}"

    def decrypt_message(encrypted: str) -> str:
        try:
            iv_str, ct_str = encrypted.split(":")
            iv = base64.b64decode(iv_str)
            ct = base64.b64decode(ct_str)
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode()
        except:
            return "[복호화 실패]"

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

@sio.on("login")
    def handle_login(sid, data):
        user_id = data.get("user_id")
        connected_users[sid]["user_id"] = user_id
        print(f"[로그인] {user_id} ({sid})")
        sio.emit("system", {"message": f"{user_id}님이 입장하셨습니다."}, skip_sid=sid)

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        receiver = data.get("receiver")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_type == "text":
            raw_text = data.get("text", "")
            encrypted_text = encrypt_message(raw_text)

            message = {
                "type": "text",
                "sender": sender,
                "receiver": receiver,
                "text": encrypted_text,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[메시지] {sender} → {receiver} (암호문 전송됨)")

        elif msg_type == "transfer":
            amount = data.get("amount")
            coin = data.get("coin", "USDT")
            memo = data.get("memo", "")

            tx_base = f"{sender}|{receiver}|{amount}|{coin}|{time.time()}"
            tx_id = hashlib.sha256(tx_base.encode()).hexdigest()[:20]
            signature = sign_tx(tx_id)

            payload = f"{amount} {coin} | {memo}"
            encrypted_payload = encrypt_message(payload)

            tx_message = {
                "type": "transfer",
                "sender": sender,
                "receiver": receiver,
                "payload": encrypted_payload,
                "tx_id": tx_id,
                "signature": signature,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(tx_message)
            sio.emit("message", tx_message, room=receiver)
            print(f"[송금] {sender} → {receiver} : {amount} {coin} (암호화됨)")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 4차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

# 고정 AES 키 (실제 서비스에선 사용자별로 다르게 관리)
SECRET_KEY = hashlib.sha256(b"zerotalk-file-encryption-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid} ({sid})")
        sio.emit("system", {"message": f"{uid}님이 접속하셨습니다."}, skip_sid=sid)

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        receiver = data.get("receiver")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_type == "text":
            encrypted = encrypt_message(data.get("text", ""))
            message = {
                "type": "text",
                "sender": sender,
                "receiver": receiver,
                "text": encrypted,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[텍스트] {sender} → {receiver} (암호화 전송)")

        elif msg_type == "transfer":
            amount = data.get("amount")
            coin = data.get("coin", "USDT")
            memo = data.get("memo", "")
            tx_id = hashlib.sha256(f"{sender}|{receiver}|{amount}|{coin}|{time.time()}".encode()).hexdigest()[:20]
            sig = sign_tx(tx_id)
            payload = encrypt_message(f"{amount} {coin} | {memo}")

            message = {
                "type": "transfer",
                "sender": sender,
                "receiver": receiver,
                "payload": payload,
                "tx_id": tx_id,
                "signature": sig,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[송금] {sender} → {receiver} : {amount} {coin} (TX: {tx_id})")

        elif msg_type == "file":
            filename = data.get("filename")
            filetype = data.get("filetype")
            filedata = data.get("base64data")

            message = {
                "type": "file",
                "sender": sender,
                "receiver": receiver,
                "filename": filename,
                "filetype": filetype,
                "base64data": filedata,
                "timestamp": timestamp
            }
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[파일] {sender} → {receiver} : {filename} ({filetype})")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 5차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

SECRET_KEY = hashlib.sha256(b"zerotalk-secure-key").digest()

# === 암호화/복호화 ===
    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

# === 메시지 ID 생성 ===
    def generate_message_id(sender, receiver, content):
        raw = f"{sender}|{receiver}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

# === 서버 및 저장소 설정 ===
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)
message_status = {}  # message_id → 상태 저장

# === 접속/퇴장 ===
@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

# === 로그인 ===
@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid} ({sid})")
        sio.emit("system", {"message": f"{uid}님이 접속하셨습니다."}, skip_sid=sid)

# === 메시지 처리 ===
@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        receiver = data.get("receiver")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_type == "text":
            plaintext = data.get("text", "")
            encrypted = encrypt_message(plaintext)
            msg_id = generate_message_id(sender, receiver, plaintext)

            message = {
                "message_id": msg_id,
                "type": "text",
                "sender": sender,
                "receiver": receiver,
                "text": encrypted,
                "timestamp": timestamp
            }
            message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
            chat_logs[receiver].append(message)
            sio.emit("message", message, room=receiver)
            print(f"[텍스트] {sender} → {receiver} (암호화 전송)")

# === 읽음/확인 상태 처리 ===
@sio.on("ack")
    def handle_ack(sid, data):
        msg_id = data.get("message_id")
        status = data.get("status")  # "read" or "delivered"
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_id in message_status:
            message_status[msg_id]["status"] = status
            message_status[msg_id]["timestamp"] = now
            print(f"[ACK] 메시지 {msg_id} → {status}")

            sender = data.get("sender")
            sio.emit("status_update", {
                "message_id": msg_id,
                "status": status,
                "timestamp": now
            }, room=sender)

# === 서버 실행 ===
    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 6차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

SECRET_KEY = hashlib.sha256(b"zerotalk-group-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}  # sid → user_id
chat_logs = defaultdict(list)  # room_id → messages
message_status = {}  # message_id → status
user_rooms = defaultdict(set)  # user_id → set(room_id)

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid} ({sid})")
        sio.emit("system", {"message": f"{uid}님 접속"}, skip_sid=sid)

@sio.on("join_room")
    def join_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.enter_room(sid, room_id)
        user_rooms[user_id].add(room_id)
        print(f"[입장] {user_id} → 방 {room_id}")

@sio.on("leave_room")
    def leave_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.leave_room(sid, room_id)
        user_rooms[user_id].discard(room_id)
        print(f"[퇴장] {user_id} → 방 {room_id}")

@sio.on("join_room")
    def join_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.enter_room(sid, room_id)
        user_rooms[user_id].add(room_id)
        print(f"[입장] {user_id} → 방 {room_id}")

@sio.on("leave_room")
    def leave_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.leave_room(sid, room_id)
        user_rooms[user_id].discard(room_id)
        print(f"[퇴장] {user_id} → 방 {room_id}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        room_id = data.get("room_id")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        participants = list(data.get("participants", []))

        if msg_type == "text":
            plaintext = data.get("text", "")
            encrypted = encrypt_message(plaintext)
            msg_id = generate_message_id(room_id, sender, plaintext)

            message = {
                "message_id": msg_id,
                "type": "text",
                "room_id": room_id,
                "sender": sender,
                "participants": participants,
                "text": encrypted,
                "timestamp": timestamp
            }
            message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
            chat_logs[room_id].append(message)
            sio.emit("message", message, room=room_id)
            print(f"[방채팅] {room_id} | {sender} → {participants}")

        elif msg_type == "transfer":
            amount = data.get("amount")
            coin = data.get("coin", "USDT")
            memo = data.get("memo", "")
            tx_id = hashlib.sha256(f"{sender}|{room_id}|{amount}|{coin}|{time.time()}".encode()).hexdigest()[:20]
            sig = sign_tx(tx_id)
            payload = encrypt_message(f"{amount} {coin} | {memo}")
            msg_id = generate_message_id(room_id, sender, payload)

            message = {
                "message_id": msg_id,
                "type": "transfer",
                "room_id": room_id,
                "sender": sender,
                "participants": participants,
                "payload": payload,
                "tx_id": tx_id,
                "signature": sig,
                "timestamp": timestamp
            }
            message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
            chat_logs[room_id].append(message)
            sio.emit("message", message, room=room_id)
            print(f"[송금] {room_id} | {sender} → {amount} {coin}")

@sio.on("ack")
    def handle_ack(sid, data):
        msg_id = data.get("message_id")
        status = data.get("status")
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_id in message_status:
            message_status[msg_id]["status"] = status
            message_status[msg_id]["timestamp"] = now
            print(f"[ACK] {msg_id} → {status}")

@sio.on("ack")
    def handle_ack(sid, data):
        msg_id = data.get("message_id")
        status = data.get("status")
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_id in message_status:
            message_status[msg_id]["status"] = status
            message_status[msg_id]["timestamp"] = now
            print(f"[ACK] {msg_id} → {status}")

SECRET_KEY = hashlib.sha256(b"zerotalk-ui-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)              # room_id → messages
message_status = {}                       # message_id → 상태
user_rooms = defaultdict(set)             # user_id → {room_id}
chat_rooms_metadata = defaultdict(dict)   # room_id → 메타정보

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        print(f"[퇴장] {user_id} ({sid})")
        connected_users.pop(sid, None)

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")
        send_chat_list(sid, uid)

@sio.on("join_room")
    def join_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.enter_room(sid, room_id)
        user_rooms[user_id].add(room_id)
        print(f"[입장] {user_id} → 방 {room_id}")
        send_chat_list(sid, user_id)

@sio.on("leave_room")
    def leave_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.leave_room(sid, room_id)
        user_rooms[user_id].discard(room_id)
        print(f"[퇴장] {user_id} → 방 {room_id}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        room_id = data.get("room_id")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        participants = list(data.get("participants", []))

        if msg_type == "text":
            text = data.get("text", "")
            encrypted = encrypt_message(text)
            msg_id = generate_message_id(room_id, sender, text)

            message = {
                "message_id": msg_id,
                "type": "text",
                "room_id": room_id,
                "sender": sender,
                "participants": participants,
                "text": encrypted,
                "timestamp": timestamp
            }
            message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
            chat_logs[room_id].append(message)
            update_room_meta(room_id, text, timestamp)
            sio.emit("message", message, room=room_id)
            print(f"[메시지] {room_id} | {sender} → {text[:10]}...")

    # 송금과 파일은 이전 구조 동일하게 추가 가능

@sio.on("ack")
    def handle_ack(sid, data):
        msg_id = data.get("message_id")
        status = data.get("status")
       now = time.strftime("%Y-%m-%d %H:%M:%S")
       if msg_id in message_status:
            message_status[msg_id]["status"] = status
            message_status[msg_id]["timestamp"] = now
           print(f"[ACK] {msg_id} → {status}")

    def update_room_meta(room_id, last_text, timestamp):
        chat_rooms_metadata[room_id]["last_message"] = last_text
        chat_rooms_metadata[room_id]["last_timestamp"] = timestamp
        chat_rooms_metadata[room_id]["unread_count"] = chat_rooms_metadata[room_id].get("unread_count", 0) + 1

    def send_chat_list(sid, user_id):
        rooms = list(user_rooms[user_id])
        result = []
        for r in rooms:
            meta = chat_rooms_metadata.get(r, {})
            result.append({
                "room_id": r,
                "last_message": meta.get("last_message", ""),
                "last_timestamp": meta.get("last_timestamp", ""),
                "unread_count": meta.get("unread_count", 0)
            })
    # 최신 순 정렬
    result = sorted(result, key=lambda x: x["last_timestamp"], reverse=True)
    sio.emit("chat_list", result, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 8차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

SECRET_KEY = hashlib.sha256(b"zerotalk-typing-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

    def current_date_str():
        return time.strftime("%Y-%m-%d")
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)
message_status = {}
user_rooms = defaultdict(set)
chat_rooms_metadata = defaultdict(dict)
room_last_date = {}  # room_id → "2024-05-02"

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        for room_id in user_rooms[user_id]:
            send_system_message(room_id, f"{user_id}님이 나가셨습니다.")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("join_room")
    def join_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.enter_room(sid, room_id)
        user_rooms[user_id].add(room_id)
        send_system_message(room_id, f"{user_id}님이 입장하셨습니다.")
        print(f"[입장] {user_id} → 방 {room_id}")

@sio.on("leave_room")
    def leave_room(sid, data):
        user_id = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        sio.leave_room(sid, room_id)
        user_rooms[user_id].discard(room_id)
        send_system_message(room_id, f"{user_id}님이 방을 나갔습니다.")
        print(f"[퇴장] {user_id} → 방 {room_id}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid, {}).get("user_id")
        room_id = data.get("room_id")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        participants = list(data.get("participants", []))

    # === 날짜 구분선 ===
        today = current_date_str()
        if room_last_date.get(room_id) != today:
            room_last_date[room_id] = today
            separator_id = generate_message_id(room_id, "system", today)
            separator_msg = {
                "message_id": separator_id,
                "type": "date_separator",
                "room_id": room_id,
                "text": today,
                "timestamp": timestamp
            }
            sio.emit("message", separator_msg, room=room_id)
            chat_logs[room_id].append(separator_msg)

    # === 일반 텍스트 메시지 ===
        if msg_type == "text":
            text = data.get("text", "")
            encrypted = encrypt_message(text)
            msg_id = generate_message_id(room_id, sender, text)

            message = {
                "message_id": msg_id,
                "type": "text",
                "room_id": room_id,
                "sender": sender,
                "participants": participants,
                "text": encrypted,
                "timestamp": timestamp
            }
            message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
            chat_logs[room_id].append(message)
            sio.emit("message", message, room=room_id)
            print(f"[텍스트] {room_id} | {sender} → {text[:10]}...")

@sio.on("typing")
    def handle_typing(sid, data):
        user_id = connected_users.get(sid)["user_id"]
        room_id = data.get("room_id")
        is_typing = data.get("typing", False)
        sio.emit("typing", {
            "room_id": room_id,
            "user_id": user_id,
            "typing": is_typing
        }, room=room_id)
        print(f"[타이핑] {user_id} ({room_id}) → {is_typing}")

@sio.on("ack")
    def handle_ack(sid, data):
        msg_id = data.get("message_id")
        status = data.get("status")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        if msg_id in message_status:
            message_status[msg_id]["status"] = status
            message_status[msg_id]["timestamp"] = now
            print(f"[ACK] {msg_id} → {status}")

    def send_system_message(room_id, text):
        sys_id = generate_message_id(room_id, "system", text)
        msg = {
            "message_id": sys_id,
            "type": "system",
            "room_id": room_id,
            "text": text,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        chat_logs[room_id].append(msg)
        sio.emit("message", msg, room=room_id)

    if __name__ == "__main__":
    from gevent import pywsgi

    print("[제로톡 9차 서버 시작] http://localhost:5000")
    server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
    server.serve_forever()

# === 암호화 유틸 ===
SECRET_KEY = hashlib.sha256(b"zerotalk-ai-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

# === 서버 설정 ===
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                       # sid → user_id
chat_logs = defaultdict(list)              # room_id → messages
message_status = {}                        # msg_id → status dict
user_rooms = defaultdict(set)              # user_id → room_ids
scheduled_messages = []                    # 예약 메시지 리스트

# === 접속 및 로그인 ===
@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")
        sio.emit("system", {"message": f"{uid}님 접속"}, skip_sid=sid)

# === 서버 시간 요청 ===
@sio.on("get_server_time")
    def handle_server_time(sid):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        sio.emit("server_time", {"timestamp": now}, to=sid)

# === 예약 메시지 등록 ===
@sio.on("schedule_message")
    def handle_schedule_message(sid, data):
        room_id = data.get("room_id")
        sender = connected_users.get(sid, {}).get("user_id")
        text = data.get("text", "")
        send_at = data.get("send_at")  # "YYYY-MM-DD HH:MM:SS"

        scheduled_messages.append({
            "room_id": room_id,
            "sender": sender,
            "text": text,
            "send_at": send_at
        })
        print(f"[예약등록] {sender} → {room_id} at {send_at}")
        sio.emit("system", {"message": f"{sender}님이 예약 메시지를 등록했습니다."}, room=room_id)

# === 일반 메시지 및 AI 자동응답 ===
@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users.get(sid)["user_id"]
        room_id = data.get("room_id")
        text = data.get("text", "")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, text)

    # 자동응답 (AI 키워드 감지)
        if "코인" in text or "송금" in text:
            auto_reply = {
                "message_id": generate_message_id(room_id, "AI", "자동응답"),
                "type": "auto",
                "room_id": room_id,
                "sender": "AI봇",
                "text": encrypt_message("코인 관련 문의는 관리자에게 연결 중입니다."),
                "timestamp": timestamp
            }
            sio.emit("message", auto_reply, room=room_id)
            chat_logs[room_id].append(auto_reply)

    # 일반 메시지 전송
        message = {
            "message_id": msg_id,
            "type": "text",
            "room_id": room_id,
            "sender": sender,
            "text": encrypt_message(text),
            "timestamp": timestamp
        }
        chat_logs[room_id].append(message)
        message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
        sio.emit("message", message, room=room_id)
        print(f"[메시지] {sender} → {room_id} : {text[:10]}...")

# === 예약 메시지 전송 스케줄러 ===
    def scheduler_loop():
        while True:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            to_send = [m for m in scheduled_messages if m["send_at"] <= now]
            for msg in to_send:
                room_id = msg["room_id"]
                sender = msg["sender"]
                text = msg["text"]
                timestamp = now
                msg_id = generate_message_id(room_id, sender, text)

                message = {
                    "message_id": msg_id,
                    "type": "scheduled",
                    "room_id": room_id,
                    "sender": sender,
                    "text": encrypt_message(text),
                    "timestamp": timestamp
                }
            sio.emit("message", message, room=room_id)
            chat_logs[room_id].append(message)
            message_status[msg_id] = {"status": "sent", "timestamp": timestamp}
            print(f"[예약발송] {sender} → {room_id} at {timestamp}")

        # 남은 예약만 유지
            scheduled_messages[:] = [m for m in scheduled_messages if m["send_at"] > now]
            time.sleep(1)

# === 서버 실행 ===
    if __name__ == "__main__":
        from gevent import pywsgi
        threading.Thread(target=scheduler_loop, daemon=True).start()
        print("[제로톡 10차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

        # === 암호화 ===
SECRET_KEY = hashlib.sha256(b"zerotalk-summary-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

# === 기본 구조 ===
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)        # room_id → messages
message_status = {}
user_rooms = defaultdict(set)
scheduled_messages = []

# === 접속/로그인 ===
@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

# === 메시지 송수신 ===
@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        text = data.get("text", "")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, text)

        message = {
            "message_id": msg_id,
            "type": "text",
            "room_id": room_id,
            "sender": sender,
            "text": encrypt_message(text),
            "timestamp": timestamp
        }

        chat_logs[room_id].append(message)
        message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
        sio.emit("message", message, room=room_id)
        print(f"[메시지] {sender} → {room_id} : {text[:10]}...")

# === 요약 요청 ===
@sio.on("summarize_chat")
    def summarize_chat(sid, data):
        room_id = data.get("room_id")
        recent = chat_logs.get(room_id, [])[-10:]
        summary = " | ".join([decrypt_message(m["text"])[:20] for m in recent if m["type"] == "text"])
        sio.emit("chat_summary", {"room_id": room_id, "summary": summary}, to=sid)
        print(f"[요약] {room_id} → {summary[:30]}...")

# === 검색 요청 ===
@sio.on("search_chat")
    def search_chat(sid, data):
        room_id = data.get("room_id")
        keyword = data.get("keyword")
        matches = []
        for m in chat_logs.get(room_id, []):
            if m["type"] == "text":
                text = decrypt_message(m["text"])
                if keyword in text:
                    matches.append({
                        "sender": m["sender"],
                        "timestamp": m["timestamp"],
                        "text": text
                    })
        sio.emit("search_results", {"room_id": room_id, "results": matches}, to=sid)
        print(f"[검색] {room_id} → '{keyword}' 결과 {len(matches)}개")

# === 서버 실행 ===
        if __name__ == "__main__":
           from gevent import pywsgi
            threading.Thread(target=lambda: time.sleep(1), daemon=True).start()
            print("[제로톡 11차 서버 시작] http://localhost:5000")
            server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
            server.serve_forever()

# === 암호화 설정 ===
SECRET_KEY = hashlib.sha256(b"zerotalk-contract-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

# === 서버 및 저장소 설정 ===
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)
message_status = {}

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        msg_type = data.get("type")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if msg_type == "transfer":
            amount = data.get("amount")
            coin = data.get("coin", "USDT")
            memo = data.get("memo", "")
            tx_id = hashlib.sha256(f"{sender}|{room_id}|{amount}|{time.time()}".encode()).hexdigest()[:20]
            sig = sign_tx(tx_id)
            payload = encrypt_message(f"{amount} {coin} | {memo}")
            msg_id = generate_message_id(room_id, sender, payload)

            message = {
                "message_id": msg_id,
                "type": "transfer",
                "room_id": room_id,
                "sender": sender,
                "payload": payload,
                "tx_id": tx_id,
                "signature": sig,
                "timestamp": timestamp
            }

            chat_logs[room_id].append(message)
            message_status[msg_id] = {"status": "sent", "timestamp": timestamp}
            sio.emit("message", message, room=room_id)
            print(f"[송금] {sender} → {room_id} : {amount} {coin} (TX: {tx_id})")

# === 계약서 자동 생성 ===
@sio.on("generate_contract")
    def generate_contract(sid, data):
        msg_id = data.get("message_id")
        for room_id, messages in chat_logs.items():
            for m in messages:
                if m["message_id"] == msg_id and m["type"] == "transfer":
                    decrypted = decrypt_message(m["payload"])
                    contract = {
                        "contract_id": f"CONTRACT-{msg_id[:8]}",
                        "sender": m["sender"],
                        "room_id": room_id,
                        "tx_id": m["tx_id"],
                        "content": decrypted,
                        "signature": m["signature"],
                        "timestamp": m["timestamp"]
                    }
                    sio.emit("contract_generated", contract, to=sid)
                    print(f"[계약서] 생성 완료 for TX: {m['tx_id']}")
                    return
        sio.emit("contract_generated", {"error": "메시지를 찾을 수 없습니다."}, to=sid)

# === 파일 복구 요청 ===
@sio.on("recover_file")
    def recover_file(sid, data):
        msg_id = data.get("message_id")
        for room_id, messages in chat_logs.items():
            for m in messages:
                if m["message_id"] == msg_id and m["type"] == "file":
                    sio.emit("file_recovered", {
                        "filename": m["filename"],
                        "filetype": m["filetype"],
                        "base64data": m["base64data"]
                    }, to=sid)
                    print(f"[파일복구] {m['filename']} 전송 완료")
                    return
        sio.emit("file_recovered", {"error": "파일을 찾을 수 없습니다."}, to=sid)

# === 실행 ===
    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 12차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

SECRET_KEY = hashlib.sha256(b"zerotalk-admin-key").digest()

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)
message_status = {}
file_archive = []  # 파일 저장 목록
blockchain_log = []  # 블록 연동용 해시

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        msg_type = data.get("type", "text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        content = data.get("text", "")

        msg_id = generate_message_id(room_id, sender, content)
        encrypted = encrypt_message(content)

        message = {
           "message_id": msg_id,
            "type": msg_type,
            "room_id": room_id,
            "sender": sender,
            "text": encrypted,
            "timestamp": timestamp
        }

        chat_logs[room_id].append(message)
        message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
        sio.emit("message", message, room=room_id)
        print(f"[메시지] {sender} → {room_id} : {content[:10]}...")

# === 관리자 명령 ===
@sio.on("admin_command")
    def admin_command(sid, data):
        cmd = data.get("cmd")
        user_id = connected_users.get(sid, {}).get("user_id")

        if user_id != "admin":
            sio.emit("admin_result", {"error": "권한 없음"}, to=sid)
            return

        if cmd == "clear_all":
            chat_logs.clear()
            file_archive.clear()
            message_status.clear()
            sio.emit("system", {"message": "[관리자] 전체 기록 삭제 완료"})
            print("[관리자] 전체 삭제")

# === 통계 출력 ===
@sio.on("get_stats")
    def get_stats(sid):
        stats = {
            "총 방 수": len(chat_logs),
            "총 메시지 수": sum(len(v) for v in chat_logs.values()),
            "파일 수": len(file_archive),
            "블록체인 해시 수": len(blockchain_log)
        }
        sio.emit("stats_result", stats, to=sid)
        print(f"[통계] {json.dumps(stats, ensure_ascii=False)}")

# === 통계 출력 ===
@sio.on("get_stats")
    def get_stats(sid):
        stats = {
            "총 방 수": len(chat_logs),
            "총 메시지 수": sum(len(v) for v in chat_logs.values()),
            "파일 수": len(file_archive),
            "블록체인 해시 수": len(blockchain_log)
        }
        sio.emit("stats_result", stats, to=sid)
        print(f"[통계] {json.dumps(stats, ensure_ascii=False)}")

# === 블록체인 해시 등록 ===
@sio.on("sync_to_block")
    def sync_to_block(sid, data):
        room_id = data.get("room_id")
        messages = chat_logs.get(room_id, [])
        block_data = json.dumps(messages, ensure_ascii=False)
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()

        blockchain_log.append({
            "room_id": room_id,
            "hash": block_hash,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        sio.emit("block_synced", {"hash": block_hash}, to=sid)
        print(f"[블록연동] {room_id} → HASH: {block_hash[:10]}...")

# === 실행 ===
    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 13차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

SECRET_KEY = hashlib.sha256(b"zerotalk-role-key").digest()
SERVER_TOKEN = "ZEROTOK_SECRET_TOKEN_7788"  # 서버용 인증키
USER_ROLES = {}  # user_id → role

    def encrypt_message(text: str) -> str:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message(encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        raw = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(raw.encode()).hexdigest()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)
message_status = {}

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        role = data.get("role", "user")
        token = data.get("auth_token")

    # 인증 토큰 확인
        if token != SERVER_TOKEN:
            sio.emit("auth_failed", {"error": "서버 인증 실패"}, to=sid)
            return

        connected_users[sid]["user_id"] = uid
        USER_ROLES[uid] = role
        print(f"[로그인] {uid} / 역할: {role}")
        sio.emit("system", {"message": f"{uid}님 접속 (권한: {role})"}, skip_sid=sid)

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        role = USER_ROLES.get(sender, "user")
        room_id = data.get("room_id")
        text = data.get("text", "")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, text)

        if role == "guest" and "송금" in text:
           sio.emit("message_blocked", {"reason": "게스트는 송금 메시지 차단됨"}, to=sid)
           return

        message = {
            "message_id": msg_id,
            "type": "text",
            "room_id": room_id,
            "sender": sender,
            "text": encrypt_message(text),
            "timestamp": timestamp
        }

        chat_logs[room_id].append(message)
        message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
        sio.emit("message", message, room=room_id)

    # 자동 외부 API 전파
    notify_external(message)
    print(f"[메시지] {sender} ({role}) → {room_id}")

# === 외부 시스템 연동 ===
    def notify_external(message):
        try:
            payload = {
                "sender": message["sender"],
                "room_id": message["room_id"],
                "text": decrypt_message(message["text"]),
                "timestamp": message["timestamp"]
            }
            res = requests.post("https://example.com/zerotalk/webhook", json=payload, timeout=2)
            if res.status_code == 200:
                print("[외부연동] 성공")
            else:
                print(f"[외부연동 실패] {res.status_code}")
        except Exception as e:
            print(f"[연동오류] {e}")

# === 서버 실행 ===
    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 14차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

    def generate_aes_key():
        return secrets.token_bytes(32)

    def encrypt_session(key, text: str) -> str:
        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_session(key, encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded)
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except:
            return "[복호화 실패]"

    def generate_message_id(room_id, sender, content):
        base = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(base.encode()).hexdigest()

io = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                  # sid → user_id
chat_logs = defaultdict(list)         # room_id → messages
message_status = {}                   # msg_id → 상태
server_state = {"mode": "normal"}     # 서버 내부 상태 관리

    def generate_message_id(room_id, sender, content):
        base = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(base.encode()).hexdigest()

    def system_bot_message(room_id, text):
        msg_id = generate_message_id(room_id, "AIBot", text)
        message = {
            "message_id": msg_id,
            "type": "bot",
            "room_id": room_id,
            "sender": "AIBot",
            "text": text,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        chat_logs[room_id].append(message)
        sio.emit("message", message, room=room_id)

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id} ({sid})")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        text = data.get("text", "")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, text)

        message = {
            "message_id": msg_id,
            "type": "text",
            "room_id": room_id,
            "sender": sender,
            "text": text,
            "timestamp": timestamp
        }
    chat_logs[room_id].append(message)
    message_status[msg_id] = {"status": "sent", "timestamp": timestamp}
    sio.emit("message", message, room=room_id)
    print(f"[메시지] {sender} → {room_id} : {text[:20]}")

    # === AI Agent 반응 트리거 ===
        if text.startswith("/"):
            handle_ai_command(room_id, sender, text)

    def handle_ai_command(room_id, sender, command_text):
        cmd = command_text.strip().lower()

        if cmd == "/모드변경":
            server_state["mode"] = "secure" if server_state["mode"] == "normal" else "normal"
            system_bot_message(room_id, f"모드가 변경되었습니다 → {server_state['mode']}")

        elif cmd.startswith("/상태"):
            system_bot_message(room_id, f"현재 서버 모드: {server_state['mode']}")

        elif cmd.startswith("/도움말"):
            guide = "/상태 /모드변경 /시간 /도움말"
            system_bot_message(room_id, f"명령어 목록: {guide}")

        elif cmd.startswith("/시간"):
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            system_bot_message(room_id, f"현재 서버 시간: {now}")

        else:
            system_bot_message(room_id, f"알 수 없는 명령입니다: {cmd}")

    def handle_ai_command(room_id, sender, command_text):
        cmd = command_text.strip().lower()

        if cmd == "/모드변경":
            server_state["mode"] = "secure" if server_state["mode"] == "normal" else "normal"
            system_bot_message(room_id, f"모드가 변경되었습니다 → {server_state['mode']}")

        elif cmd.startswith("/상태"):
            system_bot_message(room_id, f"현재 서버 모드: {server_state['mode']}")

        elif cmd.startswith("/도움말"):
            guide = "/상태 /모드변경 /시간 /도움말"
            system_bot_message(room_id, f"명령어 목록: {guide}")

        elif cmd.startswith("/시간"):
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            system_bot_message(room_id, f"현재 서버 시간: {now}")

        else:
            system_bot_message(room_id, f"알 수 없는 명령입니다: {cmd}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 16차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                        # sid → {"user_id": ..., "language": ...}
chat_logs = defaultdict(list)               # room_id → messages
user_languages = defaultdict(lambda: "ko")  # user_id → 언어 기본값

    def generate_message_id(room_id, sender, content):
        base = f"{room_id}|{sender}|{content}|{time.time()}"
        return hashlib.sha1(base.encode()).hexdigest()

    def dummy_translate(text, target_lang):
        return f"[{target_lang}] {text}"  # 실제론 API 연동

    def dummy_speech_to_text(base64_audio):
        return "이건 음성에서 변환된 텍스트입니다."  # 실제론 STT 엔진 연동

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None, "language": "ko"}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        lang = data.get("language", "ko")
        connected_users[sid]["user_id"] = uid
        connected_users[sid]["language"] = lang
        user_languages[uid] = lang
        print(f"[로그인] {uid} / 언어: {lang}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        text = data.get("text", "")
        lang = user_languages.get(sender, "ko")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        msg_id = generate_message_id(room_id, sender, text)
        translated = dummy_translate(text, lang)

        message = {
            "message_id": msg_id,
            "type": "text",
            "room_id": room_id,
            "sender": sender,
            "text": translated,
            "timestamp": timestamp
        }

        chat_logs[room_id].append(message)
        sio.emit("message", message, room=room_id)
        print(f"[메시지] {sender} ({lang}) → {translated}")

@sio.on("speech")
    def handle_speech(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        base64_audio = data.get("base64data")
        lang = connected_users[sid]["language"]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        text = dummy_speech_to_text(base64_audio)
        translated = dummy_translate(text, lang)

        msg_id = generate_message_id(room_id, sender, text)

        message = {
            "message_id": msg_id,
            "type": "speech",
            "room_id": room_id,
            "sender": sender,
            "text": translated,
            "timestamp": timestamp
        }

        chat_logs[room_id].append(message)
        sio.emit("message", message, room=room_id)
        print(f"[음성변환] {sender} → {translated}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 17차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}
chat_logs = defaultdict(list)

    def generate_message_id(room_id, sender, label):
        base = f"{room_id}|{sender}|{label}|{time.time()}"
        return hashlib.sha1(base.encode()).hexdigest()

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("video_message")
    def video_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        video_url = data.get("video_url")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, video_url)

        message = {
            "message_id": msg_id,
            "type": "video",
            "room_id": room_id,
            "sender": sender,
            "video_url": video_url,
            "timestamp": timestamp
        }

    chat_logs[room_id].append(message)
    sio.emit("message", message, room=room_id)
    print(f"[영상] {sender} → {room_id} 영상 URL 전송")

@sio.on("live_caption")
    def live_caption(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        text = data.get("caption")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, text)

        message = {
            "message_id": msg_id,
            "type": "caption",
            "room_id": room_id,
            "sender": sender,
            "caption": text,
            "timestamp": timestamp
        }

        sio.emit("caption", message, room=room_id)
        print(f"[자막] {sender} → {room_id} : {text}")

@sio.on("emoji_trigger")
    def emoji_trigger(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        emoji_type = data.get("emoji_type")  # e.g. heart, fire, wow
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg_id = generate_message_id(room_id, sender, emoji_type)

        message = {
            "message_id": msg_id,
            "type": "emoji",
            "room_id": room_id,
            "sender": sender,
            "emoji_type": emoji_type,
            "timestamp": timestamp
        }

        sio.emit("emoji", message, room=room_id)
        print(f"[AR 이모지] {sender} → {room_id} : {emoji_type}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 18차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                      # sid → user_id
channels = {}                             # channel_id → {"title": str, "type": "talk" or "broadcast", "members": set, "speakers": set}
votes = defaultdict(dict)                 # channel_id → {"title": ..., "options": ..., "results": ..., "voters": set}

    def generate_id(prefix):
        return f"{prefix}-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        for cid in channels:
            channels[cid]["members"].discard(user_id)
            channels[cid]["speakers"].discard(user_id)
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id}")

@sio.on("channel_create")
    def channel_create(sid, data):
        title = data.get("title")
        ch_type = data.get("type", "talk")
        cid = generate_id("channel")
        channels[cid] = {
            "title": title,
            "type": ch_type,
            "members": set(),
            "speakers": set()
        }
        sio.emit("channel_created", {"channel_id": cid, "title": title, "type": ch_type}, to=sid)
        print(f"[채널 생성] {cid} ({ch_type})")

@sio.on("channel_join")
    def channel_join(sid, data):
        cid = data.get("channel_id")
        uid = connected_users[sid]["user_id"]
        if cid in channels:
            channels[cid]["members"].add(uid)
            if channels[cid]["type"] == "talk":
                channels[cid]["speakers"].add(uid)
            sio.emit("channel_update", {"channel_id": cid, "members": list(channels[cid]["members"])})
            print(f"[채널 입장] {uid} → {cid}")

@sio.on("channel_leave")
    def channel_leave(sid, data):
        cid = data.get("channel_id")
        uid = connected_users[sid]["user_id"]
        if cid in channels:
            channels[cid]["members"].discard(uid)
            channels[cid]["speakers"].discard(uid)
            sio.emit("channel_update", {"channel_id": cid, "members": list(channels[cid]["members"])})
            print(f"[채널 퇴장] {uid} → {cid}")

@sio.on("channel_message")
    def channel_message(sid, data):
        cid = data.get("channel_id")
        uid = connected_users[sid]["user_id"]
        text = data.get("text")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if cid not in channels or uid not in channels[cid]["speakers"]:
            sio.emit("error", {"message": "발언권 없음"}, to=sid)
            return

        message = {
            "type": "channel_message",
            "channel_id": cid,
            "sender": uid,
            "text": text,
            "timestamp": timestamp
        }
        sio.emit("channel_message", message)
        print(f"[채널 발언] {uid} → {cid} : {text[:10]}...")

@sio.on("vote_create")
    def vote_create(sid, data):
        cid = data.get("channel_id")
        uid = connected_users[sid]["user_id"]
        title = data.get("title")
        options = data.get("options", [])
        votes[cid] = {
            "title": title,
            "options": options,
            "results": {opt: 0 for opt in options},
            "voters": set()
        }
        sio.emit("vote_started", {"channel_id": cid, "title": title, "options": options})
        print(f"[투표 시작] {cid} / {title}")

@sio.on("vote_cast")
    def vote_cast(sid, data):
        cid = data.get("channel_id")
        uid = connected_users[sid]["user_id"]
        option = data.get("option")
        if uid in votes[cid]["voters"]:
            sio.emit("error", {"message": "중복 투표"}, to=sid)
            return
        if option in votes[cid]["results"]:
            votes[cid]["results"][option] += 1
            votes[cid]["voters"].add(uid)
            print(f"[투표] {uid} → {option}")
            sio.emit("vote_result", {
                "channel_id": cid,
                "results": votes[cid]["results"]
            })

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 19차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                     # sid → user_id
shared_notes = defaultdict(str)          # room_id → 메모 텍스트
whiteboard_paths = defaultdict(list)     # room_id → [draw_paths]
live_documents = defaultdict(str)        # room_id → 현재 텍스트

    def generate_id(prefix):
        return f"{prefix}-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users[sid].get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("note_share")
    def note_share(sid, data):
        uid = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        text = data.get("text", "")
        shared_notes[room_id] = text
        sio.emit("note_update", {"room_id": room_id, "text": text}, room=room_id)
        print(f"[메모 공유] {uid} → {room_id}")

@sio.on("whiteboard_draw")
    def whiteboard_draw(sid, data):
        uid = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        draw_path = data.get("path")  # {"points": [...], "color": ..., "width": ...}
        whiteboard_paths[room_id].append(draw_path)
        sio.emit("whiteboard_update", {"room_id": room_id, "path": draw_path}, room=room_id)
        print(f"[화이트보드] {uid} → {room_id} 그리기")

@sio.on("collab_edit")
    def collab_edit(sid, data):
        uid = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        full_text = data.get("text", "")
        live_documents[room_id] = full_text
        sio.emit("doc_update", {"room_id": room_id, "text": full_text}, room=room_id)
        print(f"[문서 동기화] {uid} → {room_id}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 20차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                           # sid → user_id
shared_pdfs = defaultdict(str)                 # room_id → pdf_url
live_code = defaultdict(str)                   # room_id → code
code_versions = defaultdict(list)              # room_id → [history]
assets = defaultdict(list)                     # room_id → [{"type": ..., "name": ..., "url": ...}]

    def generate_id(prefix):
        return f"{prefix}-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
         print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users[sid].get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("pdf_share")
    def pdf_share(sid, data):
        uid = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        pdf_url = data.get("pdf_url")  # URL 또는 base64 업로드 경로
        shared_pdfs[room_id] = pdf_url
        sio.emit("pdf_update", {"room_id": room_id, "pdf_url": pdf_url}, room=room_id)
        print(f"[PDF 공유] {uid} → {room_id}")

@sio.on("code_edit")
    def code_edit(sid, data):
        uid = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        code = data.get("code", "")
        live_code[room_id] = code
        sio.emit("code_update", {"room_id": room_id, "code": code}, room=room_id)
        print(f"[코드 편집] {uid} → {room_id}")

@sio.on("version_save")
    def version_save(sid, data):
        room_id = data.get("room_id")
        content = live_code[room_id]
        code_versions[room_id].append({"code": content, "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        sio.emit("version_saved", {"room_id": room_id, "version_count": len(code_versions[room_id])}, to=sid)
        print(f"[버전 저장] {room_id} / 총 {len(code_versions[room_id])}개")

@sio.on("version_rollback")
    def version_rollback(sid, data):
        room_id = data.get("room_id")
        index = data.get("version_index")
        if 0 <= index < len(code_versions[room_id]):
            rollback = code_versions[room_id][index]["code"]
            live_code[room_id] = rollback
            sio.emit("code_update", {"room_id": room_id, "code": rollback}, room=room_id)
            print(f"[롤백] {room_id} → v{index}")
        else:
            sio.emit("error", {"message": "잘못된 버전 인덱스"}, to=sid)

@sio.on("asset_share")
    def asset_share(sid, data):
        uid = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        asset_type = data.get("type")   # e.g. image, model, video
        asset_name = data.get("name")
        asset_url = data.get("url")

        asset = {"type": asset_type, "name": asset_name, "url": asset_url}
        assets[room_id].append(asset)

        sio.emit("asset_update", {"room_id": room_id, "asset": asset}, room=room_id)
        print(f"[에셋 공유] {uid} → {room_id} ({asset_name})")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 21차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                             # sid → user_id
workspaces = {}                                   # workspace_id → {"name":..., "members": {uid: role}}
user_workspace = {}                               # user_id → workspace_id
action_log = defaultdict(list)                    # workspace_id → [logs]

    def generate_id(prefix):
        return f"{prefix}-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"

    def log_action(ws_id, user_id, action, content=""):
        entry = {
            "user": user_id,
            "action": action,
            "content": content,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        action_log[ws_id].append(entry)

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users[sid].get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("workspace_create")
    def workspace_create(sid, data):
        ws_name = data.get("name")
        uid = connected_users[sid]["user_id"]
        ws_id = generate_id("ws")
        workspaces[ws_id] = {"name": ws_name, "members": {uid: "owner"}}
        user_workspace[uid] = ws_id
        log_action(ws_id, uid, "워크스페이스 생성", ws_name)
        sio.emit("workspace_created", {"workspace_id": ws_id, "name": ws_name}, to=sid)

@sio.on("workspace_join")
    def workspace_join(sid, data):
        ws_id = data.get("workspace_id")
        uid = connected_users[sid]["user_id"]
        role = data.get("role", "viewer")
        if ws_id in workspaces:
            workspaces[ws_id]["members"][uid] = role
            user_workspace[uid] = ws_id
            log_action(ws_id, uid, "워크스페이스 참여", f"역할: {role}")
            sio.emit("workspace_joined", {"workspace_id": ws_id, "role": role}, to=sid)

@sio.on("ai_summarize")
    def ai_summarize(sid, data):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        content = data.get("text", "")
        summary = f"요약결과: {content[:50]} ..."
        log_action(ws_id, uid, "AI 요약 요청")
        sio.emit("ai_response", {"type": "summary", "result": summary}, to=sid)

@sio.on("ai_review")
    def ai_review(sid, data):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        code = data.get("code", "")
        review = "코드 리뷰: 문법 이상 없음. 성능 최적화 필요."
        log_action(ws_id, uid, "AI 코드리뷰 요청")
        sio.emit("ai_response", {"type": "review", "result": review}, to=sid)

@sio.on("ai_analyze")
    def ai_analyze(sid, data):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        asset = data.get("asset", {})
        analysis = f"에셋 분석결과: 파일명 {asset.get('name')}은 시각자료입니다."
        log_action(ws_id, uid, "AI 에셋 분석 요청")
        sio.emit("ai_response", {"type": "analyze", "result": analysis}, to=sid)

@sio.on("get_logs")
    def get_logs(sid):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        logs = action_log.get(ws_id, [])
        sio.emit("log_data", {"workspace_id": ws_id, "logs": logs}, to=sid)

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                            # sid → user_id
workspaces = {}                                  # ws_id → {"name": ..., "members": {...}, "structure": {...}}
user_workspace = {}                              # user_id → ws_id
user_dashboards = defaultdict(dict)              # user_id → {"widgets": [...], "layout": {...}}

    def generate_id(prefix):
        return f"{prefix}-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"

    def current_time():
        return time.strftime("%Y-%m-%d %H:%M:%S")

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users[sid].get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("workspace_create")
    def workspace_create(sid, data):
        uid = connected_users[sid]["user_id"]
        name = data.get("name")
        ws_id = generate_id("ws")
        workspaces[ws_id] = {
            "name": name,
            "members": {uid: "owner"},
            "structure": {
                "root": {
                    "chat": {},
                    "docs": {},
                    "vote": {},
                    "assets": {}
                }
            }
        }
        user_workspace[uid] = ws_id
        sio.emit("workspace_created", {"workspace_id": ws_id, "name": name}, to=sid)
        print(f"[워크스페이스 생성] {ws_id} / {name}")

@sio.on("module_add")
    def module_add(sid, data):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        path = data.get("path")  # e.g. ["root", "chat"]
        module_name = data.get("name")

        node = workspaces[ws_id]["structure"]
        for p in path:
           node = node.setdefault(p, {})
        node[module_name] = {}

        sio.emit("structure_updated", {"structure": workspaces[ws_id]["structure"]}, to=sid)
        print(f"[모듈 추가] {module_name} → {'/'.join(path)}")

@sio.on("dashboard_save")
    def dashboard_save(sid, data):
        uid = connected_users[sid]["user_id"]
        layout = data.get("layout")
        widgets = data.get("widgets")
        user_dashboards[uid] = {"layout": layout, "widgets": widgets}
        sio.emit("dashboard_saved", {"status": "ok"}, to=sid)
        print(f"[대시보드 저장] {uid}")

@sio.on("dashboard_load")
    def dashboard_load(sid):
        uid = connected_users[sid]["user_id"]
        dash = user_dashboards.get(uid, {"layout": {}, "widgets": []})
        sio.emit("dashboard_data", dash, to=sid)

@sio.on("get_structure")
    def get_structure(sid):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        struct = workspaces[ws_id]["structure"]
        sio.emit("structure_data", {"structure": struct}, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 23차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                        # sid → user_id
workspaces = {}                             # ws_id → {...}
user_workspace = {}                         # user_id → ws_id
workspace_groups = defaultdict(dict)        # ws_id → group_name → [user_id]
workspace_backups = defaultdict(list)       # ws_id → [snapshots]
system_alerts = []                          # 전역 시스템 알림 목록

    def generate_id(prefix):
        return f"{prefix}-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"

    def now():
        return time.strftime("%Y-%m-%d %H:%M:%S")

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users[sid].get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        connected_users[sid]["user_id"] = uid
        print(f"[로그인] {uid}")

@sio.on("group_create")
    def group_create(sid, data):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        group_name = data.get("name")
        workspace_groups[ws_id][group_name] = []
        sio.emit("group_created", {"workspace_id": ws_id, "group": group_name}, to=sid)
        print(f"[그룹 생성] {group_name} in {ws_id}")

@sio.on("group_assign")
    def group_assign(sid, data):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        group = data.get("group")
        target = data.get("target_user_id")
        workspace_groups[ws_id].setdefault(group, []).append(target)
        sio.emit("group_updated", {"group": group, "members": workspace_groups[ws_id][group]}, room=sid)
        print(f"[그룹 배정] {target} → {group} in {ws_id}")

@sio.on("get_server_stats")
    def get_server_stats(sid):
        uid = connected_users[sid]["user_id"]
        stats = {
            "접속자 수": len(connected_users),
            "워크스페이스 수": len(workspaces),
            "전체 그룹 수": sum(len(v) for v in workspace_groups.values()),
            "전체 알림": len(system_alerts),
            "시간": now()
        }
        sio.emit("server_stats", stats, to=sid)
        print(f"[통계 요청] {uid}")

@sio.on("request_backup")
    def request_backup(sid):
        uid = connected_users[sid]["user_id"]
        ws_id = user_workspace.get(uid)
        snapshot = {
            "time": now(),
            "members": workspaces.get(ws_id, {}).get("members", {}),
            "groups": workspace_groups.get(ws_id, {}),
            "structure": workspaces.get(ws_id, {}).get("structure", {})
        }
        workspace_backups[ws_id].append(snapshot)
        sio.emit("backup_complete", {"workspace_id": ws_id, "total": len(workspace_backups[ws_id])}, to=sid)
        print(f"[백업] {uid} → {ws_id}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 24차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

SECRET_KEY = hashlib.sha256(b"zerotalk-security-key").digest()
RSA_PRIVATE_KEY = RSA.generate(2048)  # 실사용시 저장된 키로 교체 필요
RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.publickey()

    def generate_aes_key():
        return hashlib.sha256(str(time.time()).encode()).digest()[:32]

    def encrypt_message_aes(key, text):
        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct).decode()

    def decrypt_message_aes(key, encoded):
        raw = base64.b64decode(encoded)
        iv, ct = raw[:16], raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()

    def sign_message_rsa(private_key, message):
        hash_obj = SHA256.new(message.encode())
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return hexlify(signature).decode()

    def verify_signature_rsa(public_key, signature, message):
        hash_obj = SHA256.new(message.encode())
        try:
            pkcs1_15.new(public_key).verify(hash_obj, unhexlify(signature))
            return True
        except (ValueError, TypeError):
            return False

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                      # sid → user_id
chat_logs = defaultdict(list)             # room_id → messages
message_status = {}                       # msg_id → status
user_pubkeys = {}                         # user_id → RSA public key

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] SID: {sid}")

@sio.event
    def disconnect(sid):
        user_id = connected_users.get(sid, {}).get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {user_id}")

@sio.on("login")
    def handle_login(sid, data):
        uid = data.get("user_id")
        signature = data.get("signature")
        public_key_pem = data.get("public_key_pem")

    # 서명 검증
        if not verify_signature_rsa(RSA_PUBLIC_KEY, signature, uid):
            sio.emit("error", {"message": "서명 검증 실패"}, to=sid)
            return

        connected_users[sid]["user_id"] = uid
        user_pubkeys[uid] = RSA.import_key(public_key_pem)
        print(f"[로그인] {uid}")

@sio.on("message")
    def handle_message(sid, data):
        sender = connected_users[sid]["user_id"]
        room_id = data.get("room_id")
        text = data.get("text", "")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        aes_key = generate_aes_key()  # AES 키는 세션마다 다르게 설정

    # 메시지 암호화
        encrypted_text = encrypt_message_aes(aes_key, text)

    # 서명 생성
        signature = sign_message_rsa(RSA_PRIVATE_KEY, text)

        msg_id = generate_message_id(room_id, sender, text)

        message = {
            "message_id": msg_id,
            "type": "text",
            "room_id": room_id,
            "sender": sender,
            "text": encrypted_text,
            "signature": signature,
            "timestamp": timestamp
            }

       chat_logs[room_id].append(message)
       message_status[msg_id] = {"status": "delivered", "timestamp": timestamp}
       sio.emit("message", message, room=room_id)
        print(f"[메시지] {sender} → {room_id} : {text[:10]}...")

@sio.on("sync_message")
    def sync_message(sid, data):
        room_id = data.get("room_id")
        messages = data.get("messages", [])
        for message in messages:
            encrypted_text = message.get("text")
            decrypted_text = decrypt_message_aes(SECRET_KEY, encrypted_text)
            message["text"] = decrypted_text  # 복호화 후 전달
            chat_logs[room_id].append(message)
        sio.emit("sync_result", {"status": "success", "room_id": room_id}, to=sid)
        print(f"[동기화] {room_id} → {len(messages)}개 메시지 수신")

    def log_action(user_id, action, content=""):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "user_id": user_id,
            "action": action,
            "content": content,
            "timestamp": timestamp
        }
    # 실제로는 DB에 저장하거나 파일로 관리
        print(f"[보안 로그] {json.dumps(log_entry)}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 25차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()
sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                    # sid → user_id
user_pubkeys = {}                       # user_id → RSA public key

    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_signature(pubkey_pem: str, message: str, signature_hex: str) -> bool:
        try:
            pubkey = RSA.import_key(pubkey_pem)
            h = SHA256.new(message.encode())
            pkcs1_15.new(pubkey).verify(h, unhexlify(signature_hex))
            return True
        except Exception:
            return False

@sio.event
    def connect(sid, environ):
        connected_users[sid] = {"user_id": None}
        print(f"[접속] {sid}")

@sio.event
    def disconnect(sid):
        uid = connected_users[sid].get("user_id", "Unknown")
        connected_users.pop(sid, None)
        print(f"[퇴장] {uid}")

@sio.on("login")
    def login(sid, data):
        uid = data.get("user_id")
        pubkey_pem = data.get("public_key_pem")
        connected_users[sid]["user_id"] = uid
        user_pubkeys[uid] = pubkey_pem
        print(f"[로그인] {uid} / 공개키 등록됨")

@sio.on("verify_proof_block")
    def verify_proof_block(sid, data):
        """
        data = {
            "user_id": "alice",
            "chain_hash": "abc123...",
            "timestamp": "2025-05-02 12:00:00",
            "signature": "abf3...",
            "signed_message": "abc123|2025-05-02 12:00:00"
        }
        """
        uid = data.get("user_id")
        pubkey = user_pubkeys.get(uid)
        message = data.get("signed_message")
        signature = data.get("signature")

        if not pubkey:
            sio.emit("verify_result", {"status": "fail", "reason": "공개키 없음"}, to=sid)
            return

        verified = verify_signature(pubkey, message, signature)

        result = {
            "status": "ok" if verified else "fail",
            "user_id": uid,
            "chain_hash": data.get("chain_hash"),
            "timestamp": data.get("timestamp"),
            "verified_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        sio.emit("verify_result", result, to=sid)
        print(f"[검증 요청] {uid} → {'성공' if verified else '실패'}")

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 29차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

connected_users = {}                              # sid → user_id
user_pubkeys = {}                                 # user_id → RSA public key
trust_chains = {}                                 # doc_id → [signed blocks]

    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_signature(pubkey_pem, message, sig_hex):
        try:
            key = RSA.import_key(pubkey_pem)
            h = SHA256.new(message.encode())
            pkcs1_15.new(key).verify(h, unhexlify(sig_hex))
            return True
        except Exception:
            return False

@sio.on("login")
    def login(sid, data):
        uid = data.get("user_id")
        pubkey_pem = data.get("public_key_pem")
        connected_users[sid] = {"user_id": uid}
        user_pubkeys[uid] = pubkey_pem
        print(f"[로그인] {uid}")

@sio.on("sign_contract_step")
    def sign_contract_step(sid, data):
        """
        data = {
            "doc_id": "contract-abc123",
            "user_id": "alice",
            "signed_message": "이전_서명|초안내용" or "초안내용",
            "signature": "abf123..."
        }
        """
        uid = data.get("user_id")
        doc_id = data.get("doc_id")
        sig = data.get("signature")
        msg = data.get("signed_message")
        pubkey = user_pubkeys.get(uid)

        if not pubkey or not verify_signature(pubkey, msg, sig):
            sio.emit("contract_sign_result", {"status": "fail", "reason": "검증 실패"}, to=sid)
            return

        chain = trust_chains.setdefault(doc_id, [])
        block = {
            "step": len(chain) + 1,
            "user_id": uid,
            "signed_message": msg,
            "signature": sig,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        chain.append(block)
        sio.emit("contract_sign_result", {"status": "ok", "doc_id": doc_id, "step": block["step"]}, to=sid)
        print(f"[계약 서명] {uid} / doc: {doc_id} / step: {block['step']}")

@sio.on("get_contract_chain")
    def get_contract_chain(sid, data):
        doc_id = data.get("doc_id")
        chain = trust_chains.get(doc_id, [])
        sio.emit("contract_chain_data", {"doc_id": doc_id, "chain": chain}, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 30차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

trust_chains = {}               # doc_id → [signed_blocks]
connected_users = {}            # sid → user_id

@sio.on("register_contract_chain")
    def register_chain(sid, data):
        doc_id = data.get("doc_id")
        chain = data.get("chain")
        trust_chains[doc_id] = chain
        sio.emit("chain_registered", {"status": "ok", "steps": len(chain)}, to=sid)

@sio.on("detect_order_conflict")
    def detect_order_conflict(sid, data):
        doc_id = data.get("doc_id")
        chain = trust_chains.get(doc_id, [])
        users_seen = set()
        conflict = False
        for b in chain:
            if b["user_id"] in users_seen:
                conflict = True
                break
            users_seen.add(b["user_id"])
        result = {"status": "ok", "conflict": conflict}
        sio.emit("order_conflict_result", result, to=sid)

@sio.on("detect_text_conflict")
    def detect_text_conflict(sid, data):
        doc_id = data.get("doc_id")
        chain = trust_chains.get(doc_id, [])
        base = chain[0]["signed_message"]
        conflict = False
        for b in chain[1:]:
            if base not in b["signed_message"]:
                conflict = True
                break
        sio.emit("text_conflict_result", {"conflict": conflict}, to=sid)

@sio.on("extract_clauses")
    def extract_clauses(sid, data):
        doc_id = data.get("doc_id")
        chain = trust_chains.get(doc_id, [])
        full_text = chain[0]["signed_message"]
        clauses = [s.strip() for s in full_text.split("•") if s.strip()]
        sio.emit("clause_list", {"clauses": clauses}, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 31차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

trust_chains = {}                    # doc_id → [signed_blocks]
contract_status_map = {}            # doc_id → "pending"/"active"/"failed"

@sio.on("condition_sign_step")
    def condition_sign_step(sid, data):
        """
        data = {
            "doc_id": "contract-123",
            "user_id": "bob",
            "signed_message": "...",
            "signature": "...",
            "condition": {
               "type": "requires_signature",
                "user_id": "alice"
            }
        }
        """
        doc_id = data["doc_id"]
        block = {
            "step": len(trust_chains.get(doc_id, [])) + 1,
            "user_id": data["user_id"],
            "signed_message": data["signed_message"],
            "signature": data["signature"],
            "condition": data["condition"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "pending"
        }
        trust_chains.setdefault(doc_id, []).append(block)
        contract_status_map[doc_id] = "pending"
        sio.emit("step_added", {"doc_id": doc_id, "step": block["step"]}, to=sid)

@sio.on("evaluate_conditions")
    def evaluate_conditions(sid, data):
        doc_id = data["doc_id"]
        chain = trust_chains.get(doc_id, [])
        signed_users = set([b["user_id"] for b in chain])
        updated = 0

        for b in chain:
            cond = b.get("condition")
            if cond and b["status"] == "pending":
                if cond["type"] == "requires_signature" and cond["user_id"] in signed_users:
                    b["status"] = "fulfilled"
                    updated += 1

        all_fulfilled = all(b.get("status", "fulfilled") == "fulfilled" for b in chain)
        contract_status_map[doc_id] = "active" if all_fulfilled else "pending"
        sio.emit("condition_result", {
            "doc_id": doc_id,
            "updated": updated,
            "status": contract_status_map[doc_id]
        }, to=sid)

@sio.on("contract_status")
    def contract_status(sid, data):
        doc_id = data["doc_id"]
        status = contract_status_map.get(doc_id, "unknown")
        sio.emit("contract_status_result", {
            "doc_id": doc_id,
            "status": status
        }, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 32차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

trust_chains = {}                         # doc_id → [signed_blocks]
contract_status_map = {}                 # doc_id → status
execution_logs = defaultdict(list)       # doc_id → [executed actions]

@sio.on("register_executable_step")
    def register_executable_step(sid, data):
        doc_id = data["doc_id"]
        block = {
            "step": len(trust_chains.get(doc_id, [])) + 1,
            "user_id": data["user_id"],
            "signed_message": data["signed_message"],
            "signature": data["signature"],
            "condition": data.get("condition"),
            "action_on_fulfill": data.get("action_on_fulfill"),
            "status": "pending",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        trust_chains.setdefault(doc_id, []).append(block)
        contract_status_map[doc_id] = "pending"
        sio.emit("step_registered", {"doc_id": doc_id, "step": block["step"]}, to=sid)

@sio.on("evaluate_and_execute")
    def evaluate_and_execute(sid, data):
        doc_id = data["doc_id"]
        chain = trust_chains.get(doc_id, [])
        signed_users = {b["user_id"] for b in chain}
        exec_results = []

        for b in chain:
            cond = b.get("condition")
            action = b.get("action_on_fulfill")

            if b["status"] == "pending" and cond:
                if cond["type"] == "requires_signature" and cond["user_id"] in signed_users:
                    b["status"] = "fulfilled"

                    if action:
                        result = execute_action(doc_id, b["user_id"], action)
                        exec_results.append(result)

        contract_status_map[doc_id] = "active" if all(b["status"] == "fulfilled" for b in chain) else "partial"
        sio.emit("execution_result", {
            "doc_id": doc_id,
            "results": exec_results,
            "status": contract_status_map[doc_id]
        }, to=sid)

    def execute_action(doc_id, user_id, action):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        act_type = action.get("type")

        if act_type == "transfer":
            result = f"[{ts}] 송금 실행: {user_id} → {action['to']} / {action['amount']} {action['coin']}"
        elif act_type == "notify":
            result = f"[{ts}] 알림: {action['message']}"
        else:
            result = f"[{ts}] 알 수 없는 명령어: {act_type}"

        execution_logs[doc_id].append(result)
        return result

@sio.on("get_execution_log")
    def get_execution_log(sid, data):
        doc_id = data["doc_id"]
        logs = execution_logs.get(doc_id, [])
        sio.emit("execution_log_data", {"doc_id": doc_id, "logs": logs}, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 33차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

sio = socketio.Server(async_mode="threading")
app = socketio.WSGIApp(sio)

trust_chains = {}                         # doc_id → [signed_blocks]
contract_status_map = {}                 # doc_id → "pending"/"active"
execution_logs = defaultdict(list)       # doc_id → [actions]

@sio.on("register_executable_step")
    def register_executable_step(sid, data):
        doc_id = data["doc_id"]
        block = {
            "step": len(trust_chains.get(doc_id, [])) + 1,
            "user_id": data["user_id"],
            "signed_message": data["signed_message"],
            "signature": data["signature"],
            "condition": data.get("condition"),
            "action_on_fulfill": data.get("action_on_fulfill"),
            "status": "pending",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        trust_chains.setdefault(doc_id, []).append(block)
        contract_status_map[doc_id] = "pending"
        sio.emit("step_registered", {"doc_id": doc_id, "step": block["step"]}, to=sid)

@sio.on("get_chain_visual")
    def get_chain_visual(sid, data):
        doc_id = data.get("doc_id")
        chain = trust_chains.get(doc_id, [])
        nodes = []
        edges = []

        for i, block in enumerate(chain):
            node_id = f"step-{i+1}"
            nodes.append({
                "id": node_id,
                "label": block["user_id"],
                "status": block.get("status", "pending")
            })

            cond = block.get("condition")
            if cond:
                target = cond.get("user_id")
                edges.append({
                    "from": node_id,
                    "to": f"step-{i+2}" if i+1 < len(chain) else node_id,
                    "condition": f"{cond['type']}: {target}",
                    "executed": block["status"] == "fulfilled"
                })

        result = {
            "nodes": nodes,
            "edges": edges,
            "contract_status": contract_status_map.get(doc_id, "unknown")
        }
        sio.emit("chain_visual_data", result, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 34차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

@sio.on("register_replayable_step")
    def register_replayable_step(sid, data):
        doc_id = data["doc_id"]
        user = data["user_id"]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        block = {
           "step": len(trust_chains.get(doc_id, [])) + 1,
            "user_id": user,
            "signed_message": data["signed_message"],
            "signature": data["signature"],
            "condition": data.get("condition"),
            "action_on_fulfill": data.get("action_on_fulfill"),
            "status": "pending",
            "timestamp": timestamp
        }

        trust_chains.setdefault(doc_id, []).append(block)

        timeline[doc_id].append({
            "timestamp": timestamp,
            "user": user,
            "action": "signed",
            "message": data["signed_message"]
        })

        sio.emit("replay_step_registered", {"doc_id": doc_id, "step": block["step"]}, to=sid)

@sio.on("evaluate_and_replay_execute")
    def evaluate_and_replay_execute(sid, data):
        doc_id = data["doc_id"]
        chain = trust_chains.get(doc_id, [])
        signed_users = {b["user_id"] for b in chain}

        for b in chain:
            cond = b.get("condition")
            act = b.get("action_on_fulfill")
            ts = time.strftime("%Y-%m-%d %H:%M:%S")

            if b["status"] == "pending" and cond:
                if cond["type"] == "requires_signature" and cond["user_id"] in signed_users:
                    b["status"] = "fulfilled"

                    timeline[doc_id].append({
                        "timestamp": ts,
                        "user": b["user_id"],
                        "action": "fulfilled_condition",
                        "triggered_by": cond["user_id"]
                    })

                    if act:
                        result = f"송금: {b['user_id']} → {act['to']} / {act['amount']} {act['coin']}"
                        execution_logs[doc_id].append(result)

                        timeline[doc_id].append({
                            "timestamp": ts,
                            "user": "system",
                            "action": "executed_transfer",
                            "to": act["to"],
                            "amount": act["amount"],
                            "coin": act["coin"]
                        })

        sio.emit("replay_executed", {"doc_id": doc_id}, to=sid)

@sio.on("get_contract_replay")
    def get_contract_replay(sid, data):
        doc_id = data["doc_id"]
        replay = timeline.get(doc_id, [])
        sio.emit("contract_replay_data", {"doc_id": doc_id, "timeline": replay}, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 35차 서버 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()

@sio.on("sign_step")
    def sign_step(sid, data):
        """
        data = {
            "doc_id": "contract-xyz",
            "user_id": "alice",
            "message": "동의합니다",
            "condition": { "type": "requires_signature", "user_id": "bob" } (optional)
        }
        """
        doc_id = data["doc_id"]
        step = {
            "step": len(contracts[doc_id]) + 1,
            "user_id": data["user_id"],
            "message": data["message"],
            "condition": data.get("condition"),
            "status": "pending",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        contracts[doc_id].append(step)
        sio.emit("step_signed", {"doc_id": doc_id, "step": step}, to=sid)

@sio.on("get_contract_chain")
    def get_contract_chain(sid, data):
        doc_id = data["doc_id"]
        chain = contracts.get(doc_id, [])
        sio.emit("contract_chain", {"doc_id": doc_id, "chain": chain}, to=sid)

@sio.on("evaluate_conditions")
    def evaluate_conditions(sid, data):
        doc_id = data["doc_id"]
        chain = contracts.get(doc_id, [])
        signed_users = {s["user_id"] for s in chain}
        updated = 0

        for s in chain:
            if s["status"] == "pending" and s.get("condition"):
                if s["condition"]["type"] == "requires_signature":
                    if s["condition"]["user_id"] in signed_users:
                        s["status"] = "fulfilled"
                        updated += 1

        sio.emit("condition_evaluated", {"doc_id": doc_id, "updated": updated}, to=sid)

    if __name__ == "__main__":
        from gevent import pywsgi
        print("[제로톡 36차 CORE 미니멀 시작] http://localhost:5000")
        server = pywsgi.WSGIServer(("0.0.0.0", 5000), app)
        server.serve_forever()