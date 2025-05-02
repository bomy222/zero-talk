import json
import os
import time
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

SECURITY_FILE = "security_data.json"
TOKEN_FILE = "token_data.json"
IP_BLOCK_DAYS = 7
MAX_FAILED_ATTEMPTS = 3
EMAIL_LIMIT_PER_DAY = 5
SUPPORT_EMAIL = "support@zerotalk.ai"

# 기본 로딩/저장 함수
    def load_json(path):
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except:
                return {}

    def save_json(path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

# 1. IP 차단 관련
    def is_ip_blocked(ip):
        data = load_json(SECURITY_FILE)
        info = data.get(ip)
        if not info:
            return False
        last_attempt = datetime.strptime(info["last_attempt"], "%Y-%m-%d")
        if info["count"] >= MAX_FAILED_ATTEMPTS:
            if datetime.now() - last_attempt < timedelta(days=IP_BLOCK_DAYS):
                return True
        return False

    def register_failed_attempt(ip):
    data = load_json(SECURITY_FILE)
    today = datetime.now().strftime("%Y-%m-%d")
    if ip not in data:
        data[ip] = {"count": 1, "last_attempt": today}
    else:
        if data[ip]["last_attempt"] != today:
            data[ip]["count"] = 1
        else:
            data[ip]["count"] += 1
        data[ip]["last_attempt"] = today
    save_json(SECURITY_FILE, data)

    def reset_ip_attempt(ip):
        data = load_json(SECURITY_FILE)
        if ip in data:
            data[ip]["count"] = 0
            save_json(SECURITY_FILE, data)

# 2. 이메일 인증 횟수 제한
    def can_request_email(email):
        data = load_json(SECURITY_FILE)
        today = datetime.now().strftime("%Y-%m-%d")
        if email not in data:
            data[email] = {"count": 1, "date": today}
        else:
            if data[email]["date"] != today:
               data[email]["count"] = 1
               data[email]["date"] = today
            elif data[email]["count"] >= EMAIL_LIMIT_PER_DAY:
                return False
        else:
            data[email]["count"] += 1
    save_json(SECURITY_FILE, data)
    return True

# 3. 이메일 발송 요청 템플릿
    def send_email(recipient_email, code):
    try:
        msg = MIMEText(f"ZeroTalk 인증 코드: {code}")
        msg["Subject"] = "ZeroTalk 이메일 인증"
        msg["From"] = SUPPORT_EMAIL
        msg["To"] = recipient_email

        server = smtplib.SMTP("smtp.example.com", 587)  # 실제 SMTP 주소 필요
        server.starttls()
        server.login("your_email@example.com", "your_password")  # 실제 계정
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("이메일 전송 실패:", e)
        return False

# 4. 토큰 키 생성 및 저장
    def generate_token(username):
        token = hashlib.sha256((username + str(time.time())).encode()).hexdigest()[:12]
        tokens = load_json(TOKEN_FILE)
        tokens[username] = token
        save_json(TOKEN_FILE, tokens)
        return token

    def validate_token(username, token_input):
        tokens = load_json(TOKEN_FILE)
        return tokens.get(username) == token_input

# 5. 기기 변경 감지용 (IP + 시간 기준)
    def detect_device_change(ip, username):
        data = load_json("device_log.json")
        now = time.time()
        if username not in data:
            data[username] = {"ip": ip, "last_login": now}
            save_json("device_log.json", data)
            return False  # 최초 로그인은 변경 아님
        prev_ip = data[username]["ip"]
    if ip != prev_ip:
        return True
    return False