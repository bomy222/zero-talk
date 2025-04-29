from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'zerotalk_super_secret'
socketio = SocketIO(app)

users_db = {}  # username: {password, wallet}
chats_db = {}  # room: [ {user, message, timestamp} ]
transactions_db = []  # {sender, receiver, amount, time}

# JWT 토큰용 헬퍼
def encode_auth_token(username):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': username
        }
        return jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired.'
    except jwt.InvalidTokenError:
        return 'Invalid token.'

# 로그인 세션 체크
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        username = decode_auth_token(token)
        if not username or username not in users_db:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@login_required
def home():
    username = decode_auth_token(session['token'])
    return render_template('index.html', username=username, users=list(users_db.keys()))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_db.get(username)
        if user and check_password_hash(user['password'], password):
            session['token'] = encode_auth_token(username)
            return redirect(url_for('home'))
        else:
            return "로그인 실패: 잘못된 아이디 또는 비밀번호."
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username not in users_db:
            users_db[username] = {
                'password': generate_password_hash(password),
                'wallet': 10000  # 기본 지갑 금액
            }
            return redirect(url_for('login'))
        else:
            return "이미 존재하는 사용자명입니다."
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# 송금 API
@app.route('/send_coin', methods=['POST'])
@login_required
def send_coin():
    data = request.json
    sender = decode_auth_token(session['token'])
    receiver = data.get('receiver')
    amount = int(data.get('amount', 0))
    if receiver not in users_db:
        return jsonify({"status": "fail", "message": "받는 사용자가 존재하지 않습니다."})
    if users_db[sender]['wallet'] < amount:
        return jsonify({"status": "fail", "message": "잔액이 부족합니다."})
    users_db[sender]['wallet'] -= amount
    users_db[receiver]['wallet'] += amount
    transactions_db.append({
        'sender': sender,
        'receiver': receiver,
        'amount': amount,
        'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    return jsonify({"status": "success", "message": "송금 완료"})

# 대시보드 화면
@app.route('/dashboard')
@login_required
def dashboard():
    username = decode_auth_token(session['token'])
    return render_template('dashboard.html', username=username, users=list(users_db.keys()), transactions=transactions_db)

# 소켓 통신
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f"{data['username']} 님이 입장했습니다."}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f"{data['username']} 님이 퇴장했습니다."}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    room = data['room']
    username = data['username']
    message = data['message']
    if room not in chats_db:
        chats_db[room] = []
    chats_db[room].append({
        'user': username,
        'message': message,
        'timestamp': datetime.datetime.now().strftime('%H:%M')
    })
    emit('receive_message', {'user': username, 'message': message}, room=room)

if __name__ == "__main__":
    socketio.run(app, debug=True)