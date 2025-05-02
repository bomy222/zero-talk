import os
import json
import time
import hashlib
from datetime import datetime, timedelta

SECURITY_DB = "security/security_data.json"
TOKEN_DB = "security/token_store.json"
DEVICE_LOG = "security/device_log.json"
WALLET_LOG = "security/wallet_transfer_log.json"

MAX_FAILED_ATTEMPTS = 5
IP_BAN_DURATION = 86400  # 초 (1일)
TOKEN_EXPIRY_DAYS = 180
ALLOW_TEMP_TOKEN = False

os.makedirs("security", exist_ok=True)

# JSON 로드/저장
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
            json.dump(data, f, indent=4, ensure_ascii=False)

# 1. IP 차단 감지 시스템
    def register_ip_failure(ip):
        db = load_json(SECURITY_DB)
        now = int(time.time())
        if ip not in db:
            db[ip] = {"failures": 1, "last": now}
        else:
            db[ip]["failures"] += 1
            db[ip]["last"] = now
        save_json(SECURITY_DB, db)
    
    def is_ip_blocked(ip):
        db = load_json(SECURITY_DB)
        info = db.get(ip)
        if not info:
            return False
        if info["failures"] >= MAX_FAILED_ATTEMPTS:
            if time.time() - info["last"] < IP_BAN_DURATION:
                return True
        return False

# 2. 고유 토큰 생성 및 검증
    def generate_token(username):
        raw = f"{username}-{time.time()}"
        token = hashlib.sha256(raw.encode()).hexdigest()[:16]
        db = load_json(TOKEN_DB)
        db[username] = {
            "token": token,
            "created": datetime.now().strftime("%Y-%m-%d"),
            "expires": (datetime.now() + timedelta(days=TOKEN_EXPIRY_DAYS)).strftime("%Y-%m-%d")
            }
        save_json(TOKEN_DB, db)
        return token

    def validate_token(username, token):
        db = load_json(TOKEN_DB)
        record = db.get(username)
        if not record:
            return False
        if record["token"] != token:
            return False
        if datetime.strptime(record["expires"], "%Y-%m-%d") < datetime.now():
            return False
        return True

# 3. 기기 변경 감지 (IP 기준)
    def log_device(username, ip):
        logs = load_json(DEVICE_LOG)
        if username not in logs:
            logs[username] = []
        if ip not in logs[username]:
            logs[username].append(ip)
        save_json(DEVICE_LOG, logs)

    def get_known_devices(username):
        logs = load_json(DEVICE_LOG)
        return logs.get(username, [])

# 4. 코인 송금 로그 기록
    def log_wallet_transfer(sender, receiver, coin, amount, txid):
        logs = load_json(WALLET_LOG)
        entry = {
            "from": sender,
            "to": receiver,
            "coin": coin,
            "amount": amount,
            "txid": txid,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        if "history" not in logs:
            logs["history"] = []
        logs["history"].append(entry)
        save_json(WALLET_LOG, logs)

    def get_transfer_history(username=None):
        logs = load_json(WALLET_LOG)
        history = logs.get("history", [])
        if username:
            return [h for h in history if h["from"] == username or h["to"] == username]
        return history

# 5. QR 로그인/토큰 발급 보안 제한
    def regenerate_token(username):
        return generate_token(username)

    def expire_token(username):
        db = load_json(TOKEN_DB)
        if username in db:
            del db[username]
            save_json(TOKEN_DB, db)

# === P2P 코인 송금 요청 기록 ===

    def record_p2p_transfer(sender, receiver, coin_type, amount, tx_id, memo=None):
        log_path = "logs/p2p_transfers.json"
        log_entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "coin": coin_type,
            "amount": amount,
            "tx_id": tx_id,
            "memo": memo
            }

        logs = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []

        logs.append(log_entry)
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)

# === 유효 코인 리스트 체크 ===

SUPPORTED_COINS = ["BTC", "ETH", "SOL", "XRP", "DOGE", "TON", "USDT", "ADA", "DOT", "MATIC"]

    def is_valid_coin(coin_type):
        return coin_type.upper() in SUPPORTED_COINS

# === 송금 유효성 검증 ===

    def validate_transfer(sender, receiver, amount, coin_type):
        if sender == receiver:
            return False, "동일 사용자간 송금 불가"
        if not is_valid_coin(coin_type):
            return False, "지원되지 않는 코인"
        if amount <= 0:
            return False, "송금 금액 오류"
        return True, "확인됨"

# === 송금요청 시 암호화된 트랜잭션 ID 생성 ===

    def generate_tx_id(sender, receiver, coin, amount):
        payload = f"{sender}|{receiver}|{coin}|{amount}|{time.time()}"
        return hashlib.sha256(payload.encode()).hexdigest()[:20]

# === 송금 요청 핸들러 ===

    def request_transfer(sender, receiver, coin, amount, memo=None):
        is_ok, msg = validate_transfer(sender, receiver, amount, coin)
        if not is_ok:
            return {"status": "error", "message": msg}

        tx_id = generate_tx_id(sender, receiver, coin, amount)
        record_p2p_transfer(sender, receiver, coin, amount, tx_id, memo)
        return {
            "status": "ok",
            "tx_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "coin": coin,
            "amount": amount
            }

# ============ [1] 송금 상태 조회 ============
    def get_transfer_status(tx_id):
        log_path = "logs/p2p_transfers.json"
        if not os.path.exists(log_path):
            return {"status": "error", "message": "내역 없음"}

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
            for entry in logs:
                if entry["tx_id"] == tx_id:
                    return {"status": "ok", "data": entry}
        except:
            return {"status": "error", "message": "파일 오류"}

        return {"status": "error", "message": "해당 TX ID 없음"}


# ============ [2] 송금 내역 목록 조회 ============
    def get_user_transfers(user_id):
        log_path = "logs/p2p_transfers.json"
        result = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
                for entry in logs:
                    if entry["sender"] == user_id or entry["receiver"] == user_id:
                    result.append(entry)
            except:
                return {"status": "error", "message": "내역 불러오기 실패"}
        return {"status": "ok", "count": len(result), "data": result}

# ============ [3] 2FA 토큰 인증 (간이형) ============
# 보통 사용자 비밀번호 or OTP 형태, 여기선 토큰 키 해시 인증 구조로 설계
    def verify_token_signature(user_id, token, secret_key):
        data = f"{user_id}|{token}|{secret_key}"
        hash_check = hashlib.sha256(data.encode()).hexdigest()
        return hash_check[-6:]  # 마지막 6자리로 인증번호처럼 활용

    def confirm_token(user_input_code, user_id, token, secret_key):
        correct_code = verify_token_signature(user_id, token, secret_key)
        return user_input_code == correct_code

# ============ [4] 메신저 전달 메시지 생성 ============
    def generate_transfer_message(sender, receiver, coin, amount, tx_id):
        msg = f"[{sender}]님이 [{receiver}]님에게 {coin} {amount}개를 송금했습니다.\n"
        msg += f"TX ID: {tx_id}\n보낸 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        return msg

# ============ [5] 통합 송금 요청 (토큰 확인 포함) ============
    def secure_request_transfer(sender, receiver, coin, amount, token, user_input_code, secret_key, memo=None):
    # 1. 기본 유효성 검사
        is_ok, msg = validate_transfer(sender, receiver, amount, coin)
        if not is_ok:
            return {"status": "error", "message": msg}

    # 2. 토큰 검증
        if not confirm_token(user_input_code, sender, token, secret_key):
            return {"status": "error", "message": "인증 실패: 토큰 코드 불일치"}

    # 3. TX 생성 및 기록
        tx_id = generate_tx_id(sender, receiver, coin, amount)
        record_p2p_transfer(sender, receiver, coin, amount, tx_id, memo)

    # 4. 메시지 생성
        msg = generate_transfer_message(sender, receiver, coin, amount, tx_id)

        return {
            "status": "ok",
            "tx_id": tx_id,
            "message": msg,
            "sender": sender,
            "receiver": receiver,
            "coin": coin,
            "amount": amount
            }

wallet_path = "logs/user_wallets.json"  # 로컬 지갑 상태 파일

# ============ [1] 지갑 불러오기 ============
    def load_wallets():
        if os.path.exists(wallet_path):
            try:
                with open(wallet_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return {}
        return {}

# ============ [2] 지갑 저장하기 ============
    def save_wallets(wallets):
        with open(wallet_path, "w", encoding="utf-8") as f:
            json.dump(wallets, f, indent=4, ensure_ascii=False)

# ============ [3] 사용자 잔고 확인 ============
    def get_user_balance(user_id, coin):
        wallets = load_wallets()
        return wallets.get(user_id, {}).get(coin.upper(), 0)

# ============ [4] 잔고 차감 및 추가 ============
    def update_user_balance(sender, receiver, coin, amount):
        wallets = load_wallets()
        coin = coin.upper()

    # 지갑이 없으면 자동 생성
        if sender not in wallets:
            wallets[sender] = {}
        if receiver not in wallets:
            wallets[receiver] = {}

    # 부족 시 오류
        sender_balance = wallets[sender].get(coin, 0)
        if sender_balance < amount:
            return False, "잔고 부족"

    # 차감 및 수신자 추가
        wallets[sender][coin] = round(sender_balance - amount, 8)
        wallets[receiver][coin] = round(wallets[receiver].get(coin, 0) + amount, 8)

        save_wallets(wallets)
            return True, "잔고 업데이트 성공"
    
    def wallet_transfer_request(sender, receiver, coin, amount, token, user_input_code, secret_key, memo=None):
    
    # 1. 유효성
        is_ok, msg = validate_transfer(sender, receiver, amount, coin)
        if not is_ok:
            return {"status": "error", "message": msg}

    # 2. 인증
        if not confirm_token(user_input_code, sender, token, secret_key):
            return {"status": "error", "message": "토큰 인증 실패"}

    # 3. 잔고 차감 시도
        success, result_msg = update_user_balance(sender, receiver, coin, amount)
        if not success:
            return {"status": "error", "message": result_msg}

    # 4. 트랜잭션 기록
        tx_id = generate_tx_id(sender, receiver, coin, amount)
        record_p2p_transfer(sender, receiver, coin, amount, tx_id, memo)

    # 5. 전달 메시지
        msg = generate_transfer_message(sender, receiver, coin, amount, tx_id)

        return {
            "status": "ok",
            "tx_id": tx_id,
            "message": msg,
            "sender": sender,
            "receiver": receiver,
            "coin": coin,
            "amount": amount,
            "balance": {
                "sender": get_user_balance(sender, coin),
                "receiver": get_user_balance(receiver, coin)
            }
            }

import os, json, time, hashlib, base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === 기본 설정 ===
wallet_path = "logs/user_wallets.json"
log_path = "logs/p2p_transfers.json"
AES_KEY = b'my_super_secretkey_32bytes_len!!'

SUPPORTED_COINS = ["BTC", "ETH", "SOL", "XRP", "DOGE", "TON", "USDT", "ADA", "DOT", "MATIC"]

# === 유틸 함수 ===
def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    return data[:-ord(data[-1])]

def encrypt_wallet_data(data):
    raw = pad(json.dumps(data)).encode()
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(raw)
    return base64.b64encode(iv + encrypted).decode()

def decrypt_wallet_data(enc_data):
    enc = base64.b64decode(enc_data.encode())
    iv = enc[:16]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc[16:])
    return json.loads(unpad(decrypted.decode()))

# === 지갑 처리 ===
def load_wallets():
    if os.path.exists(wallet_path):
        try:
            with open(wallet_path, "r", encoding="utf-8") as f:
                return decrypt_wallet_data(f.read())
        except:
            return {}
    return {}

def save_wallets(wallets):
    with open(wallet_path, "w", encoding="utf-8") as f:
        f.write(encrypt_wallet_data(wallets))

def get_user_balance(user_id, coin):
    wallets = load_wallets()
    return wallets.get(user_id, {}).get(coin.upper(), 0)

def update_user_balance(sender, receiver, coin, amount):
    wallets = load_wallets()
    coin = coin.upper()
    if sender not in wallets:
        wallets[sender] = {}
    if receiver not in wallets:
        wallets[receiver] = {}

    sender_balance = wallets[sender].get(coin, 0)
    if sender_balance < amount:
        return False, "잔고 부족"

    wallets[sender][coin] = round(sender_balance - amount, 8)
    wallets[receiver][coin] = round(wallets[receiver].get(coin, 0) + amount, 8)

    save_wallets(wallets)
    return True, "업데이트 완료"

# === 수수료 ===
def calculate_fee(amount, rate=0.005, minimum=0.0001):
    fee = round(amount * rate, 8)
    return max(fee, minimum)

# === 송금 검증 ===
def is_valid_coin(coin_type):
    return coin_type.upper() in SUPPORTED_COINS

def validate_transfer(sender, receiver, amount, coin_type):
    if sender == receiver:
        return False, "동일 사용자 간 송금 불가"
    if not is_valid_coin(coin_type):
        return False, "지원되지 않는 코인"
    if amount <= 0:
        return False, "잘못된 금액"
    return True, "확인됨"

# === 트랜잭션 ===
def generate_tx_id(sender, receiver, coin, amount):
    payload = f"{sender}|{receiver}|{coin}|{amount}|{time.time()}"
    return hashlib.sha256(payload.encode()).hexdigest()[:20]

def record_p2p_transfer(sender, receiver, coin_type, amount, tx_id, memo=None):
    log_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sender": sender,
        "receiver": receiver,
        "coin": coin_type,
        "amount": amount,
        "tx_id": tx_id,
        "memo": memo
    }

    logs = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except:
            logs = []

    logs.append(log_entry)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)

# === 2FA 토큰 인증 ===
def verify_token_signature(user_id, token, secret_key):
    data = f"{user_id}|{token}|{secret_key}"
    hash_check = hashlib.sha256(data.encode()).hexdigest()
    return hash_check[-6:]

def confirm_token(user_input_code, user_id, token, secret_key):
    return user_input_code == verify_token_signature(user_id, token, secret_key)

# === 메시지 생성 ===
def generate_transfer_message(sender, receiver, coin, amount, tx_id):
    msg = f"[{sender}]님이 [{receiver}]님에게 {coin} {amount}개 송금\nTX ID: {tx_id}\n시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    return msg

# === 최종 송금 처리 ===
def protected_wallet_transfer(sender, receiver, coin, amount, token, user_input_code, secret_key, memo=None):
    if not confirm_token(user_input_code, sender, token, secret_key):
        return {"status": "error", "message": "2FA 인증 실패"}

    is_ok, msg = validate_transfer(sender, receiver, amount, coin)
    if not is_ok:
        return {"status": "error", "message": msg}

    fee = calculate_fee(amount)
    real_amount = amount - fee
    if real_amount <= 0:
        return {"status": "error", "message": "수수료로 인해 송금 불가"}

    success, result_msg = update_user_balance(sender, receiver, coin, real_amount)
    if not success:
        return {"status": "error", "message": result_msg}

    tx_id = generate_tx_id(sender, receiver, coin, real_amount)
    record_p2p_transfer(sender, receiver, coin, real_amount, tx_id, memo)
    msg = generate_transfer_message(sender, receiver, coin, real_amount, tx_id)

    return {
        "status": "ok",
        "tx_id": tx_id,
        "amount": real_amount,
        "fee": fee,
        "sender_balance": get_user_balance(sender, coin),
        "receiver_balance": get_user_balance(receiver, coin),
        "message": msg
    }

import os, json, time, hashlib, base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === 설정 ===
wallet_path = "logs/user_wallets.json"
log_path = "logs/p2p_transfers.json"
pending_path = "logs/pending_transfers.json"
auto_rules_path = "logs/auto_rules.json"
AES_KEY = b'my_super_secretkey_32bytes_len!!'

SUPPORTED_COINS = ["BTC", "ETH", "SOL", "XRP", "DOGE", "TON", "USDT", "ADA", "DOT", "MATIC"]

# === 유틸 (암호화, 해시 등) ===
    def pad(data):
        return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

    def unpad(data):
        return data[:-ord(data[-1])]

    def encrypt_wallet_data(data):
        raw = pad(json.dumps(data)).encode()
        iv = get_random_bytes(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)
        return base64.b64encode(iv + encrypted).decode()

    def decrypt_wallet_data(enc_data):
        enc = base64.b64decode(enc_data.encode())
        iv = enc[:16]
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[16:])
        return json.loads(unpad(decrypted.decode()))

    def generate_tx_id(sender, receiver, coin, amount):
        payload = f"{sender}|{receiver}|{coin}|{amount}|{time.time()}"
        return hashlib.sha256(payload.encode()).hexdigest()[:20]

# === 토큰 인증 ===
    def verify_token_signature(user_id, token, secret_key):
        data = f"{user_id}|{token}|{secret_key}"
        hash_check = hashlib.sha256(data.encode()).hexdigest()
        return hash_check[-6:]

    def confirm_token(user_input_code, user_id, token, secret_key):
       return user_input_code == verify_token_signature(user_id, token, secret_key)

# === 유효성 검사 ===
    def is_valid_coin(coin_type):
        return coin_type.upper() in SUPPORTED_COINS

    def validate_transfer(sender, receiver, amount, coin_type):
        if sender == receiver:
            return False, "동일 사용자 간 송금 불가"
        if not is_valid_coin(coin_type):
            return False, "지원되지 않는 코인"
        if amount <= 0:
            return False, "잘못된 금액"
        return True, "확인됨"

# === 수수료 ===
    def calculate_fee(amount, rate=0.005, minimum=0.0001):
        fee = round(amount * rate, 8)
        return max(fee, minimum)

# === 지갑 처리 ===
    def load_wallets():
        if os.path.exists(wallet_path):
            try:
                with open(wallet_path, "r", encoding="utf-8") as f:
                    return decrypt_wallet_data(f.read())
            except:
                return {}
        return {}

    def save_wallets(wallets):
        with open(wallet_path, "w", encoding="utf-8") as f:
            f.write(encrypt_wallet_data(wallets))

    def get_user_balance(user_id, coin):
        wallets = load_wallets()
        return wallets.get(user_id, {}).get(coin.upper(), 0)

    def update_user_balance(sender, receiver, coin, amount):
        wallets = load_wallets()
        coin = coin.upper()
        if sender not in wallets:
            wallets[sender] = {}
        if receiver not in wallets:
            wallets[receiver] = {}

        sender_balance = wallets[sender].get(coin, 0)
        if sender_balance < amount:
            return False, "잔고 부족"

        wallets[sender][coin] = round(sender_balance - amount, 8)
        wallets[receiver][coin] = round(wallets[receiver].get(coin, 0) + amount, 8)
        save_wallets(wallets)
        return True, "업데이트 완료"

# === 기록 ===
    def record_p2p_transfer(sender, receiver, coin_type, amount, tx_id, memo=None):
        log_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sender": sender,
        "receiver": receiver,
        "coin": coin_type,
        "amount": amount,
        "tx_id": tx_id,
        "memo": memo
        }

        logs = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []

        logs.append(log_entry)
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)

# === 메시지 ===
    def generate_transfer_message(sender, receiver, coin, amount, tx_id):
        msg = f"[{sender}]님이 [{receiver}]님에게 {coin} {amount}개 송금\nTX ID: {tx_id}\n시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        return msg

# === 6차 핵심 ===

# 1. 송금 요청 → 대기 상태 저장
    def save_pending_request(sender, receiver, coin, amount, tx_id, memo=None):
        data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "coin": coin,
            "amount": amount,
            "tx_id": tx_id,
            "memo": memo,
            "status": "pending",
            "approved": False
            }
        pendings = []
        if os.path.exists(pending_path):
            try:
                with open(pending_path, "r", encoding="utf-8") as f:
                    pendings = json.load(f)
            except:
                pendings = []
        pendings.append(data)
        with open(pending_path, "w", encoding="utf-8") as f:
            json.dump(pendings, f, indent=4, ensure_ascii=False)

# 2. 송금 요청 생성
    def create_transfer_request(sender, receiver, coin, amount, token, user_input_code, secret_key, memo=None):
        if not confirm_token(user_input_code, sender, token, secret_key):
           return {"status": "error", "message": "2FA 인증 실패"}

        is_ok, msg = validate_transfer(sender, receiver, amount, coin)
        if not is_ok:
            return {"status": "error", "message": msg}

        fee = calculate_fee(amount)
        real_amount = amount - fee
        if real_amount <= 0:
            return {"status": "error", "message": "수수료로 인해 송금 불가"}

        tx_id = generate_tx_id(sender, receiver, coin, real_amount)
        return try_auto_approve(sender, receiver, coin, real_amount, tx_id, memo)

# 3. 수신자 수락 처리
    def approve_transfer(tx_id):
        if not os.path.exists(pending_path):
            return {"status": "error", "message": "보류 중인 요청 없음"}

        with open(pending_path, "r", encoding="utf-8") as f:
    pendings = json.load(f)

    updated = []
    executed = False
        for entry in pendings:
            if entry["tx_id"] == tx_id and not entry["approved"]:
                success, msg = update_user_balance(entry["sender"], entry["receiver"], entry["coin"], entry["amount"])
                if not success:
                    return {"status": "error", "message": msg}

            record_p2p_transfer(entry["sender"], entry["receiver"], entry["coin"], entry["amount"], tx_id, entry.get("memo"))
                    entry["approved"] = True
                    entry["status"] = "done"
                    executed = True
            updated.append(entry)

        with open(pending_path, "w", encoding="utf-8") as f:
            json.dump(updated, f, indent=4, ensure_ascii=False)

            if executed:
                return {"status": "ok", "message": "송금 완료됨"}
            return {"status": "error", "message": "요청 없음 또는 이미 승인됨"}

# 4. 자동 수락 조건
    def get_auto_rules(user_id):
        if os.path.exists(auto_rules_path):
            try:
                with open(auto_rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get(user_id, {})
            except:
                return {}
        return {}

    def is_auto_approved(receiver, sender, amount):
        rules = get_auto_rules(receiver)
        max_limit = rules.get("auto_accept_limit", 0)
        whitelist = rules.get("whitelist", [])
            return sender in whitelist or amount <= max_limit

# 5. 자동 수락 시도
    def try_auto_approve(sender, receiver, coin, amount, tx_id, memo=None):
        if is_auto_approved(receiver, sender, amount):
            success, msg = update_user_balance(sender, receiver, coin, amount)
            if not success:
            return {"status": "error", "message": msg}
        record_p2p_transfer(sender, receiver, coin, amount, tx_id, memo)
            return {"status": "ok", "message": "자동 승인됨", "tx_id": tx_id}
    else:
        save_pending_request(sender, receiver, coin, amount, tx_id, memo)
        return {"status": "pending", "message": f"{receiver}님의 수락 대기 중", "tx_id": tx_id}

import os, json, time, hashlib, base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === 기본 설정 ===
wallet_path = "logs/user_wallets.json"
log_path = "logs/p2p_transfers.json"
pending_path = "logs/pending_transfers.json"
chat_path = "logs/chat_messages.json"
AES_KEY = b'my_super_secretkey_32bytes_len!!'
SUPPORTED_COINS = ["BTC", "ETH", "SOL", "XRP", "DOGE", "TON", "USDT", "ADA", "DOT", "MATIC"]

# === 암호화 유틸 ===
    def pad(data):
        return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

    def unpad(data):
        return data[:-ord(data[-1])]

    def encrypt_message(text, key):
        raw = pad(text).encode()
        iv = get_random_bytes(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)
        return base64.b64encode(iv + encrypted).decode()

    def decrypt_message(cipher_text, key):
        try:
            enc = base64.b64decode(cipher_text.encode())
            iv = enc[:16]
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(enc[16:])
            return unpad(decrypted.decode())
        except:
            return "[복호화 실패]"

# === 2FA 인증 ===
    def verify_token_signature(user_id, token, secret_key):
        data = f"{user_id}|{token}|{secret_key}"
        hash_check = hashlib.sha256(data.encode()).hexdigest()
        return hash_check[-6:]

    def confirm_token(user_input_code, user_id, token, secret_key):
        return user_input_code == verify_token_signature(user_id, token, secret_key)

# === 지갑 ===
    def encrypt_wallet_data(data):
        raw = pad(json.dumps(data)).encode()
        iv = get_random_bytes(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)
        return base64.b64encode(iv + encrypted).decode()

    def decrypt_wallet_data(enc_data):
       enc = base64.b64decode(enc_data.encode())
        iv = enc[:16]
       cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[16:])
        return json.loads(unpad(decrypted.decode()))

    def load_wallets():
        if os.path.exists(wallet_path):
            try:
                with open(wallet_path, "r", encoding="utf-8") as f:
                   return decrypt_wallet_data(f.read())
            except:
                return {}
        return {}

    def save_wallets(wallets):
        with open(wallet_path, "w", encoding="utf-8") as f:
            f.write(encrypt_wallet_data(wallets))

    def get_user_balance(user_id, coin):
        wallets = load_wallets()
        return wallets.get(user_id, {}).get(coin.upper(), 0)

    def update_user_balance(sender, receiver, coin, amount):
        wallets = load_wallets()
        coin = coin.upper()
        if sender not in wallets:
            wallets[sender] = {}
        if receiver not in wallets:
            wallets[receiver] = {}

        sender_balance = wallets[sender].get(coin, 0)
        if sender_balance < amount:
            return False, "잔고 부족"

        wallets[sender][coin] = round(sender_balance - amount, 8)
        wallets[receiver][coin] = round(wallets[receiver].get(coin, 0) + amount, 8)
        save_wallets(wallets)
        return True, "업데이트 완료"

# === 수수료 ===
    def calculate_fee(amount, rate=0.005, minimum=0.0001):
        fee = round(amount * rate, 8)
        return max(fee, minimum)

# === 검증 ===
    def is_valid_coin(coin_type):
        return coin_type.upper() in SUPPORTED_COINS

    def validate_transfer(sender, receiver, amount, coin_type):
        if sender == receiver:
            return False, "동일 사용자 간 송금 불가"
        if not is_valid_coin(coin_type):
            return False, "지원되지 않는 코인"
        if amount <= 0:
            return False, "잘못된 금액"
        return True, "확인됨"

# === 트랜잭션 생성 ===
    def generate_tx_id(sender, receiver, coin, amount):
        payload = f"{sender}|{receiver}|{coin}|{amount}|{time.time()}"
       return hashlib.sha256(payload.encode()).hexdigest()[:20]

    def record_p2p_transfer(sender, receiver, coin_type, amount, tx_id, memo=None):
        log_entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "coin": coin_type,
            "amount": amount,
            "tx_id": tx_id,
            "memo": memo
            }
        logs = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []
        logs.append(log_entry)
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)

# === 송금 요청 (보류 저장) ===
    def save_pending_request(sender, receiver, coin, amount, tx_id, memo=None):
        data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "coin": coin,
            "amount": amount,
            "tx_id": tx_id,
            "memo": memo,
            "status": "pending",
            "approved": False
            }
        pendings = []
        if os.path.exists(pending_path):
            try:
                with open(pending_path, "r", encoding="utf-8") as f:
                   pendings = json.load(f)
            except:
                pendings = []
        pendings.append(data)
        with open(pending_path, "w", encoding="utf-8") as f:
            json.dump(pendings, f, indent=4, ensure_ascii=False)

# === 메시지 암호화 및 저장 ===
    def save_chat_message(sender, receiver, encrypted_msg):
        data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "message": encrypted_msg
            }
        messages = []
        if os.path.exists(chat_path):
            try:
                with open(chat_path, "r", encoding="utf-8") as f:
                    messages = json.load(f)
            except:
                messages = []
        messages.append(data)
        with open(chat_path, "w", encoding="utf-8") as f:
            json.dump(messages, f, indent=4, ensure_ascii=False)

    def create_encrypted_transfer_message(sender, receiver, coin, amount, tx_id, key):
        raw = f"[송금요청]\n보낸이: {sender}\n받는이: {receiver}\n코인: {coin} {amount}\nTX: {tx_id}"
        encrypted = encrypt_message(raw, key)
        save_chat_message(sender, receiver, encrypted)
        return encrypted

# === 자동 수락 조건 (생략 가능 — 기본 수동 승인 기반)

# === 송금 요청 (암호화 메시지 포함) ===
    def create_transfer_request(sender, receiver, coin, amount, token, user_input_code, secret_key, encryption_key, memo=None):
        if not confirm_token(user_input_code, sender, token, secret_key):
            return {"status": "error", "message": "2FA 인증 실패"}
        is_ok, msg = validate_transfer(sender, receiver, amount, coin)
        if not is_ok:
            return {"status": "error", "message": msg}
        fee = calculate_fee(amount)
        real_amount = amount - fee
        if real_amount <= 0:
            return {"status": "error", "message": "수수료로 인해 송금 불가"}

    tx_id = generate_tx_id(sender, receiver, coin, real_amount)
    save_pending_request(sender, receiver, coin, real_amount, tx_id, memo)
    create_encrypted_transfer_message(sender, receiver, coin, real_amount, tx_id, encryption_key)
    return {"status": "pending", "tx_id": tx_id, "message": f"{receiver}님의 수락 대기 중"}

# === 수신자 수락 (TX ID로) ===
    def approve_transfer(tx_id):
        if not os.path.exists(pending_path):
            return {"status": "error", "message": "보류 요청 없음"}

        with open(pending_path, "r", encoding="utf-8") as f:
            pendings = json.load(f)

        updated = []
        executed = False
        for entry in pendings:
            if entry["tx_id"] == tx_id and not entry["approved"]:
                success, msg = update_user_balance(entry["sender"], entry["receiver"], entry["coin"], entry["amount"])
                if not success:
                    return {"status": "error", "message": msg}
                record_p2p_transfer(entry["sender"], entry["receiver"], entry["coin"], entry["amount"], tx_id, entry.get("memo"))
                entry["approved"] = True
                entry["status"] = "done"
                executed = True
            updated.append(entry)

        with open(pending_path, "w", encoding="utf-8") as f:
            json.dump(updated, f, indent=4, ensure_ascii=False)

        if executed:
            return {"status": "ok", "message": "송금 승인 완료"}
        return {"status": "error", "message": "TX 없음 또는 이미 처리됨"}

# === 메시지 복호화 및 읽기 ===
    def get_all_messages_for_user(user_id, key):
        if not os.path.exists(chat_path):
            return []
        with open(chat_path, "r", encoding="utf-8") as f:
            msgs = json.load(f)
        results = []
        for msg in msgs:
            if msg["receiver"] == user_id:
                decrypted = decrypt_message(msg["message"], key)
                results.append({
                    "time": msg["time"],
                    "from": msg["sender"],
                    "text": decrypted
                    })
        return results

import os, json, base64, hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === 기본 설정 ===
chat_path = "logs/chat_messages.json"
ai_policy_path = "logs/ai_auto_rules.json"

# === 암호화 유틸 (AES256 CBC) ===
    def pad(data):
        return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

    def unpad(data):
        return data[:-ord(data[-1])]

    def encrypt_message(text, key):
        raw = pad(text).encode()
        iv = get_random_bytes(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)
        return base64.b64encode(iv + encrypted).decode()

    def decrypt_message(cipher_text, key):
        try:
            enc = base64.b64decode(cipher_text.encode())
            iv = enc[:16]
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(enc[16:])
            return unpad(decrypted.decode())
        except:
            return "[복호화 실패]"

# === 메시지 저장 ===
    def save_chat_message(sender, receiver, encrypted_msg):
        data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "receiver": receiver,
            "message": encrypted_msg
            }
        messages = []
        if os.path.exists(chat_path):
            try:
                with open(chat_path, "r", encoding="utf-8") as f:
                    messages = json.load(f)
            except:
                messages = []
        messages.append(data)
        with open(chat_path, "w", encoding="utf-8") as f:
            json.dump(messages, f, indent=4, ensure_ascii=False)

# === 메시지 복호화 후 전체 조회 ===
    def get_all_messages_for_user(user_id, key):
        if not os.path.exists(chat_path):
            return []
        with open(chat_path, "r", encoding="utf-8") as f:
            msgs = json.load(f)
        results = []
        for msg in msgs:
            if msg["receiver"] == user_id:
                decrypted = decrypt_message(msg["message"], key)
                results.append({
                    "time": msg["time"],
                    "from": msg["sender"],
                    "text": decrypted
                    })
        return results

# === [1] 메시지 요약기 (간이 AI 역할) ===
    def summarize_transfer_message(message_text):
        lines = message_text.split('\n')
        summary = {}
        for line in lines:
            if '보낸이' in line:
                summary['sender'] = line.split(':')[-1].strip()
            if '받는이' in line:
                summary['receiver'] = line.split(':')[-1].strip()
            if '코인' in line:
                parts = line.split(':')[-1].strip().split()
                if len(parts) == 2:
                    summary['coin'] = parts[0]
                    summary['amount'] = float(parts[1])
            if 'TX' in line:
                summary['tx_id'] = line.split(':')[-1].strip()
        return summary

# === [2] 정책 불러오기 / 저장 ===
    def load_ai_rules(user_id):
        if os.path.exists(ai_policy_path):
            try:
                with open(ai_policy_path, "r", encoding="utf-8") as f:
                    rules = json.load(f)
                return rules.get(user_id, {})
            except:
                return {}
        return {}

    def save_ai_rules(user_id, new_rules):
        rules = {}
        if os.path.exists(ai_policy_path):
            try:
                with open(ai_policy_path, "r", encoding="utf-8") as f:
                    rules = json.load(f)
            except:
                rules = {}
        rules[user_id] = new_rules
        with open(ai_policy_path, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=4, ensure_ascii=False)

# === [3] 판단 로직 ===
    def ai_should_auto_approve(user_id, sender, amount):
        rules = load_ai_rules(user_id)
        whitelist = rules.get("whitelist", [])
        max_amount = rules.get("max_amount", 0)

        if sender in whitelist:
            return "auto"
        if amount <= max_amount:
            return "auto"
        if amount > max_amount * 2:
            return "reject"
        return "manual"

# === [4] AI 메시지 분석 후 결정 추천 ===
    def ai_process_message_and_decide(user_id, encrypted_msg, decryption_key):
        plain_text = decrypt_message(encrypted_msg, decryption_key)
        summary = summarize_transfer_message(plain_text)
        if not summary:
            return {"status": "error", "message": "메시지 분석 실패"}

        sender = summary['sender']
        amount = summary['amount']
        decision = ai_should_auto_approve(user_id, sender, amount)

        return {
            "decision": decision,  # "auto" | "manual" | "reject"
            "summary": summary,
            "original": plain_text
            }

import os, json, hashlib, zipfile
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import pyminizip

# === [1] 전자서명 생성 ===
    def generate_signature(user_id, tx_id, secret_key):
        raw_data = f"{user_id}|{tx_id}|{secret_key}"
        return hashlib.sha256(raw_data.encode()).hexdigest()

# === [2] PDF 영수증 생성 ===
    def create_pdf_receipt(tx_data, signature, file_path="logs/receipt.pdf"):
        c = canvas.Canvas(file_path, pagesize=A4)
        c.setFont("Helvetica", 12)

        y = 800
        c.drawString(50, y, f"[P2P 송금 영수증]")
        y -= 30
        for key, value in tx_data.items():
            c.drawString(50, y, f"{key} : {value}")
            y -= 20

        c.drawString(50, y - 10, f"전자서명 : {signature}")
        c.save()

# === [3] ZIP 백업 (logs 폴더 전체 압축) ===
    def zip_logs_with_password(output_zip="logs_backup.zip", password="securepass"):
        files_to_zip = []
        for root, dirs, files in os.walk("logs"):
            for file in files:
                full_path = os.path.join(root, file)
                files_to_zip.append(full_path)

        pyminizip.compress_multiple(files_to_zip, [], output_zip, password, 5)

# === [4] 전체 예시 실행 ===
    def generate_receipt_and_backup(user_id, tx_data, secret_key, zip_password):
    # 1. 서명 생성
        signature = generate_signature(user_id, tx_data["tx_id"], secret_key)

    # 2. PDF 영수증 출력
        create_pdf_receipt(tx_data, signature)

    # 3. 전체 logs 폴더 암호 ZIP 백업
        zip_logs_with_password("logs_backup.zip", zip_password)

        return {
            "status": "ok",
            "signature": signature,
            "pdf": "logs/receipt.pdf",
            "zip": "logs_backup.zip"
            }

import os, json, hashlib
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# === [1] 다중 서명 생성 (송금자 + 수신자) ===
    def generate_dual_signature(sender_id, receiver_id, tx_id, sender_key, receiver_key):
        sig_sender = hashlib.sha256(f"{sender_id}|{tx_id}|{sender_key}".encode()).hexdigest()
        sig_receiver = hashlib.sha256(f"{receiver_id}|{tx_id}|{receiver_key}".encode()).hexdigest()
        return {
            "sender_signature": sig_sender,
            "receiver_signature": sig_receiver
    }

# === [2] 다중 서명 포함 PDF 영수증 생성 ===
    def create_dual_signed_pdf(tx_data, sigs, file_path="logs/receipt_signed.pdf"):
        c = canvas.Canvas(file_path, pagesize=A4)
        c.setFont("Helvetica", 12)

        y = 800
        c.drawString(50, y, f"[P2P 송금 영수증 - 다중 서명]")
        y -= 30
        for key, value in tx_data.items():
            c.drawString(50, y, f"{key} : {value}")
            y -= 20

        y -= 10
        c.drawString(50, y, f"송금자 서명 : {sigs['sender_signature']}")
        y -= 20
        c.drawString(50, y, f"수신자 서명 : {sigs['receiver_signature']}")
        c.save()

# === [3] PDF 해시 로그 기록 저장 ===
    def log_pdf_hash(pdf_path, tx_id):
        with open(pdf_path, "rb") as f:
            content = f.read()
            hash_value = hashlib.sha256(content).hexdigest()

        log_file = "logs/pdf_hashes.json"
        logs = {}
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = {}

        logs[tx_id] = {
            "file": pdf_path,
            "hash": hash_value,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)

# === [4] PDF 파일의 진본성 검증 ===
    def verify_pdf_integrity(pdf_path, tx_id):
        if not os.path.exists(pdf_path):
            return False

        with open(pdf_path, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        log_file = "logs/pdf_hashes.json"
        if not os.path.exists(log_file):
            return False

        with open(log_file, "r", encoding="utf-8") as f:
            logs = json.load(f)

        expected_hash = logs.get(tx_id, {}).get("hash")
        return current_hash == expected_hash

# === [5] 전체 흐름 통합 실행 ===
    def generate_fully_signed_receipt(sender, receiver, tx_data, sender_key, receiver_key):
    # 1. 다중 서명 생성
        sigs = generate_dual_signature(sender, receiver, tx_data["tx_id"], sender_key, receiver_key)

    # 2. PDF 생성
        pdf_path = "logs/receipt_signed.pdf"
        create_dual_signed_pdf(tx_data, sigs, pdf_path)

    # 3. 해시 로그 저장
        log_pdf_hash(pdf_path, tx_data["tx_id"])

        return {
            "status": "ok",
            "pdf": pdf_path,
            "sender_signature": sigs["sender_signature"],
            "receiver_signature": sigs["receiver_signature"]
            }

import os, json, hashlib
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import xml.etree.ElementTree as ET
import qrcode

# === [1] 다중 서명 생성 ===
    def generate_dual_signature(sender_id, receiver_id, tx_id, sender_key, receiver_key):
        sig_sender = hashlib.sha256(f"{sender_id}|{tx_id}|{sender_key}".encode()).hexdigest()
        sig_receiver = hashlib.sha256(f"{receiver_id}|{tx_id}|{receiver_key}".encode()).hexdigest()
        return {
            "sender_signature": sig_sender,
            "receiver_signature": sig_receiver
            }

# === [2] PDF 생성 (QR코드 포함) ===
    def create_pdf_with_qr(tx_data, signatures, qr_content, file_path="logs/receipt_signed_qr.pdf"):
    # QR 생성 및 저장
        qr = qrcode.make(qr_content)
        qr_path = "logs/temp_qr.png"
        qr.save(qr_path)

    # PDF 생성
        c = canvas.Canvas(file_path, pagesize=A4)
        c.setFont("Helvetica", 12)

        y = 800
        c.drawString(50, y, "[P2P 송금 영수증 - QR 포함]")
        y -= 30
        for key, value in tx_data.items():
            c.drawString(50, y, f"{key} : {value}")
            y -= 20

        y -= 10
        c.drawString(50, y, f"송금자 서명 : {signatures['sender_signature']}")
        y -= 20
        c.drawString(50, y, f"수신자 서명 : {signatures['receiver_signature']}")
        y -= 150

        qr_img = ImageReader(qr_path)
        c.drawImage(qr_img, 50, y, width=120, height=120)
        c.save()

    os.remove(qr_path)

# === [3] JSON 출력 ===
    def export_json(tx_data, signatures, file_path="logs/receipt.json"):
        data = {
            "transaction": tx_data,
            "signatures": signatures
            }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

# === [4] XML 출력 ===
    def export_xml(tx_data, signatures, file_path="logs/receipt.xml"):
        root = ET.Element("receipt")

        tx = ET.SubElement(root, "transaction")
        for k, v in tx_data.items():
            ET.SubElement(tx, k).text = str(v)

        sig = ET.SubElement(root, "signatures")
        for k, v in signatures.items():
            ET.SubElement(sig, k).text = str(v)

        tree = ET.ElementTree(root)
        tree.write(file_path, encoding="utf-8", xml_declaration=True)

# === [5] AI 진술 자동 생성 ===
    def generate_statement(tx_data):
        s = tx_data["sender"]
        r = tx_data["receiver"]
        c = tx_data["coin"]
        a = tx_data["amount"]
        t = tx_data["time"]
        txid = tx_data["tx_id"]

        return (
            f"나는 {t}에 {s}라는 이름으로, {r}에게 {c} {a}개를 "
            f"송금하였고, 이 거래는 TX ID '{txid}'로 기록되었다. "
            f"본 거래는 자발적으로 이루어졌으며, 그 내용은 진실이다."
            )

# === [6] 전체 법적 패키지 생성 ===
    def generate_legal_package(sender, receiver, tx_data, sender_key, receiver_key):
    # 1. 서명 생성
        sigs = generate_dual_signature(sender, receiver, tx_data["tx_id"], sender_key, receiver_key)

    # 2. PDF with QR
        qr_content = f"TX_ID:{tx_data['tx_id']}|HASH:{sigs['sender_signature'][:10]}"
        create_pdf_with_qr(tx_data, sigs, qr_content)

    # 3. JSON & XML 출력
        export_json(tx_data, sigs)
        export_xml(tx_data, sigs)

    # 4. 진술 생성
        statement = generate_statement(tx_data)
        with open("logs/statement.txt", "w", encoding="utf-8") as f:
            f.write(statement)

        return {
            "status": "ok",
            "pdf": "logs/receipt_signed_qr.pdf",
            "json": "logs/receipt.json",
            "xml": "logs/receipt.xml",
            "statement": "logs/statement.txt"
            }

import os, json, hashlib
from datetime import datetime

# === [1] 파일 해시 생성 (PDF, JSON 등) ===
    def hash_file_for_token(path):
        with open(path, "rb") as f:
            content = f.read()
            return hashlib.sha256(content).hexdigest()

# === [2] NFT 메타데이터 생성 (ERC-721 스타일) ===
    def generate_nft_metadata(tx_data, file_hash, tx_id, save_path="logs/nft_metadata.json"):
        metadata = {
            "name": f"송금 증명 NFT - {tx_id}",
            "description": f"{tx_data['sender']} → {tx_data['receiver']} / {tx_data['coin']} {tx_data['amount']} 송금",
            "external_url": "",
            "attributes": [
                {"trait_type": "Sender", "value": tx_data["sender"]},
                {"trait_type": "Receiver", "value": tx_data["receiver"]},
                {"trait_type": "Coin", "value": tx_data["coin"]},
                {"trait_type": "Amount", "value": tx_data["amount"]},
                {"trait_type": "TX_ID", "value": tx_id},
                {"trait_type": "Timestamp", "value": tx_data["time"]},
                {"trait_type": "FileHash", "value": file_hash}
                ]
            }

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4, ensure_ascii=False)

        return metadata

# === [3] 블록체인 메시지 (TON 또는 ETH 로그 용) ===
    def generate_ton_message(tx_id, file_hash):
        return f"[P2P NFT Proof] TX_ID: {tx_id} | HASH: {file_hash[:16]}..."

# === [4] NFT + 해시 + 메시지 전체 흐름 ===
    def generate_nft_and_chain_log(tx_data, proof_file_path, chain="ton"):
        tx_id = tx_data["tx_id"]
        file_hash = hash_file_for_token(proof_file_path)

        metadata = generate_nft_metadata(tx_data, file_hash, tx_id)

        if chain == "ton":
            message = generate_ton_message(tx_id, file_hash)
            print("[TON 블록체인 메시지] :", message)

        elif chain == "eth":
            message = f"emit NFTProof('{tx_id}', '{file_hash}')"
            print("[Ethereum 스마트컨트랙트 로그] :", message)

        else:
            message = f"UNSUPPORTED_CHAIN for TX {tx_id}"

        return {
            "status": "ok",
            "metadata": metadata,
            "file_hash": file_hash,
            "blockchain_message": message
            }

import os, json, hashlib
from web3 import Web3

# === [1] 파일 해시 생성 ===
    def hash_file_for_token(path):
        with open(path, "rb") as f:
            content = f.read()
            return hashlib.sha256(content).hexdigest()

# === [2] NFT 메타데이터 생성 (ERC-721 스타일) ===
    def generate_nft_metadata(tx_data, file_hash, tx_id, save_path="logs/nft_metadata.json"):
        metadata = {
            "name": f"송금 증명 NFT - {tx_id}",
            "description": f"{tx_data['sender']} → {tx_data['receiver']} / {tx_data['coin']} {tx_data['amount']} 송금",
            "external_url": "",
            "attributes": [
                {"trait_type": "Sender", "value": tx_data["sender"]},
                {"trait_type": "Receiver", "value": tx_data["receiver"]},
                {"trait_type": "Coin", "value": tx_data["coin"]},
                {"trait_type": "Amount", "value": tx_data["amount"]},
                {"trait_type": "TX_ID", "value": tx_id},
                {"trait_type": "Timestamp", "value": tx_data["time"]},
                {"trait_type": "FileHash", "value": file_hash}
                ]
            }

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4, ensure_ascii=False)

        return metadata

# === [3] 스마트컨트랙트 배포 (ERC721) ===
    def deploy_contract(w3, abi_path, bin_path, admin_address, private_key):
        with open(abi_path, 'r') as f:
            abi = json.load(f)
        with open(bin_path, 'r') as f:
            bytecode = f.read()

        contract = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx = contract.constructor().build_transaction({
            "from": admin_address,
            "nonce": w3.eth.get_transaction_count(admin_address),
            "gas": 3000000,
            "gasPrice": w3.to_wei('5', 'gwei')
            })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt.contractAddress

# === [4] NFT 민팅 함수 ===
    def mint_nft(w3, contract_address, abi, to_address, metadata_uri, admin_address, private_key):
        contract = w3.eth.contract(address=contract_address, abi=abi)
        tx = contract.functions.mint(to_address, metadata_uri).build_transaction({
            "from": admin_address,
            "nonce": w3.eth.get_transaction_count(admin_address),
            "gas": 200000,
            "gasPrice": w3.to_wei('5', 'gwei')
            })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return tx_hash.hex()

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

    contract ProofNFT is ERC721URIStorage {
        uint256 public nextTokenId;
        mapping(address => bool) public admins;
        address public superAdmin;

        constructor() ERC721("Proof NFT", "PNFT") {
            superAdmin = msg.sender;
            admins[msg.sender] = true;
            }

        modifier onlyAdmin() {
            require(admins[msg.sender], "not admin");
            _;
            }

        function setAdmin(address user, bool status) external {
            require(msg.sender == superAdmin, "only superAdmin");
            admins[user] = status;
            }

        function mint(address to, string memory uri) external onlyAdmin {
            _safeMint(to, nextTokenId);
            _setTokenURI(nextTokenId, uri);
            nextTokenId++;
            }

        function burn(uint256 tokenId) external onlyAdmin {
            _burn(tokenId);
            }

        function transferSuperAdmin(address newAdmin) external {
            require(msg.sender == superAdmin, "only superAdmin");
            superAdmin = newAdmin;
            }
    }

    def ai_decide_and_mint(w3, contract_address, abi, tx_data, metadata_uri, admin_address, private_key, decision="mint"):
        contract = w3.eth.contract(address=contract_address, abi=abi)

        if decision == "mint":
            tx = contract.functions.mint(admin_address, metadata_uri).build_transaction({
                "from": admin_address,
                "nonce": w3.eth.get_transaction_count(admin_address),
                "gas": 200000,
                "gasPrice": w3.to_wei('5', 'gwei')
                })
        elif decision == "burn":
            token_id = tx_data["token_id"]
            tx = contract.functions.burn(token_id).build_transaction({
                "from": admin_address,
                "nonce": w3.eth.get_transaction_count(admin_address),
                "gas": 100000,
                "gasPrice": w3.to_wei('5', 'gwei')
                })
        else:
            return {"status": "skip"}

        signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return {"status": decision, "tx_hash": tx_hash.hex()}

import json, hashlib
from datetime import datetime
from eth_account import Account
from eth_account.messages import encode_defunct

# === [1] 서명 메시지 생성 ===
    def generate_signature_message(tx_data):
        message = (
            f"송금자: {tx_data['sender']}\n"
            f"수신자: {tx_data['receiver']}\n"
            f"금액: {tx_data['amount']} {tx_data['coin']}\n"
            f"TX_ID: {tx_data['tx_id']}\n"
            f"시간: {tx_data['time']}"
        )
        return message

# === [2] 오프체인 서명 생성 ===
    def sign_message(message, private_key):
        msg = encode_defunct(text=message)
        signed = Account.sign_message(msg, private_key=private_key)
        return signed.signature.hex()

# === [3] 서명 검증 ===
    def verify_signature(message, signature_hex, expected_address):
        msg = encode_defunct(text=message)
        signer = Account.recover_message(msg, signature=signature_hex)
        return signer.lower() == expected_address.lower()

# === [4] zkProof 구조 (SHA256 해시 기반) ===
    def generate_proof_hash(tx_data):
        data = f"{tx_data['sender']}|{tx_data['receiver']}|{tx_data['amount']}|{tx_data['coin']}|{tx_data['tx_id']}|{tx_data['time']}"
        return hashlib.sha256(data.encode()).hexdigest()

# === [5] JSON 증명서 자동 생성 ===
    def export_proof_certificate(tx_data, signature_hex, signer_address, proof_hash, path="logs/proof_certificate.json"):
        cert = {
            "type": "송금 증명서",
            "tx_data": tx_data,
            "signature": signature_hex,
            "signer": signer_address,
            "hash_proof": proof_hash,
            "issued_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=4, ensure_ascii=False)
        return path

import os, json, hashlib, requests
from datetime import datetime
from web3 import Web3

# === [1] 파일 해시 생성 (SHA256 기반) ===
    def hash_file_for_token(path):
        with open(path, "rb") as f:
            content = f.read()
            return hashlib.sha256(content).hexdigest()

# === [2] 다국어 증명서 생성 (JSON) ===
    def export_multilang_certificate(tx_data, file_hash, languages=["ko", "en", "ja"], base_path="logs/"):
        templates = {
            "ko": f"{tx_data['time']}에 {tx_data['sender']}님이 {tx_data['receiver']}님에게 {tx_data['coin']} {tx_data['amount']}를 송금하였고, TX ID는 {tx_data['tx_id']}입니다.",
            "en": f"On {tx_data['time']}, {tx_data['sender']} sent {tx_data['amount']} {tx_data['coin']} to {tx_data['receiver']}. TX ID: {tx_data['tx_id']}.",
            "ja": f"{tx_data['time']}に{tx_data['sender']}は{tx_data['receiver']}に{tx_data['coin']} {tx_data['amount']}を送金しました。TX ID: {tx_data['tx_id']}。"
        }

        results = {}
        for lang in languages:
            cert = {
               "lang": lang,
                "text": templates[lang],
                "tx": tx_data,
                "file_hash": file_hash
            }
            filename = f"{base_path}certificate_{lang}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(cert, f, indent=4, ensure_ascii=False)
            results[lang] = filename

        return results

# === [3] IPFS 업로드 (Pinata) ===
    def upload_to_ipfs(file_path, pinata_api_key, pinata_secret):
        url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
        headers = {
            "pinata_api_key": pinata_api_key,
            "pinata_secret_api_key": pinata_secret
        }
        with open(file_path, 'rb') as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            return response.json()["IpfsHash"]
        else:
            raise Exception(f"IPFS 업로드 실패: {response.text}")

# === [4] 스마트컨트랙트 등록 함수 (Web3.py) ===
    def register_proof_hash(w3, contract_address, abi, tx_id, file_hash, admin_address, private_key):
        contract = w3.eth.contract(address=contract_address, abi=abi)
        tx = contract.functions.registerProof(tx_id, file_hash).build_transaction({
            "from": admin_address,
            "nonce": w3.eth.get_transaction_count(admin_address),
            "gas": 200000,
            "gasPrice": w3.to_wei('5', 'gwei')
            })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return tx_hash.hex()

import hashlib

# === [1] zkProof 생성 (조건 만족 여부만 증명) ===
def generate_zk_proof(secret_data, public_condition):
    """
    secret_data = {
        "receiver": "bob",
        "amount": 1.25,
        "memo": "private business"
    }
    public_condition = {
        "min_amount": 1
    }
    """
    assert secret_data["amount"] >= public_condition["min_amount"]

    hidden = f"{secret_data['receiver']}|{secret_data['amount']}|{secret_data['memo']}"
    proof = hashlib.sha256(hidden.encode()).hexdigest()
    return proof

# === [2] 다자 서명 생성 (Multisig 구조) ===
def generate_multisig(tx_id, signer_keys):
    """
    signer_keys = ["keyA", "keyB", "keyC"]
    """
    signatures = []
    for key in signer_keys:
        data = f"{tx_id}|{key}"
        sig = hashlib.sha256(data.encode()).hexdigest()
        signatures.append(sig)
    return signatures

# === [3] DAO 검증 로직 (zk + 서명 수 기준) ===
def dao_verify_zk(proof, required_hashes, multisigs, required_signers=2):
    """
    proof = zk 해시
    required_hashes = DAO가 인정하는 해시 리스트
    multisigs = 실제 제출된 서명 리스트
    """
    if proof not in required_hashes:
        return "proof invalid"
    if len(multisigs) < required_signers:
        return "not enough signatures"
    return "proof accepted"

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProofDAO {
    struct Proof {
        address owner;
        string txId;
        uint256 timestamp;
        bool active;
        uint256 votesFor;
        uint256 votesAgainst;
    }
    
    mapping(string => Proof) public proofs;
    mapping(address => mapping(string => bool)) public hasVoted;
    uint256 public ttl = 3 days;

    modifier onlyOwner(string memory txId) {
        require(msg.sender == proofs[txId].owner, "Not owner");
        _;
    }

    function submitProof(string memory txId) public {
        proofs[txId] = Proof(msg.sender, txId, block.timestamp, true, 0, 0);
    }

    function vote(string memory txId, bool support) public {
        require(!hasVoted[msg.sender][txId], "Already voted");
        require(proofs[txId].active, "Inactive proof");

        hasVoted[msg.sender][txId] = true;
        if (support) {
            proofs[txId].votesFor++;
        } else {
            proofs[txId].votesAgainst++;
        }
    }

    function checkExpiry(string memory txId) public view returns (bool) {
        return block.timestamp > proofs[txId].timestamp + ttl;
    }

    function invalidate(string memory txId) public onlyOwner(txId) {
        require(checkExpiry(txId), "Not expired");
        proofs[txId].active = false;
    }
    }

import time

class LocalDAO:
    def __init__(self):
        self.votes = {}
        self.proofs = {}
        self.ttl = 3 * 24 * 60 * 60  # 3일 in seconds

    def submit(self, tx_id, sender):
        now = int(time.time())
        self.proofs[tx_id] = {
            "owner": sender,
            "timestamp": now,
            "active": True,
            "votes_for": 0,
            "votes_against": 0,
            "voters": set()
        }

    def vote(self, tx_id, voter, support=True):
        proof = self.proofs.get(tx_id)
        if not proof or not proof["active"]:
            return "inactive or unknown"

        if voter in proof["voters"]:
            return "already voted"

        proof["voters"].add(voter)
        if support:
            proof["votes_for"] += 1
        else:
            proof["votes_against"] += 1
        return "vote accepted"

    def check_expiry(self, tx_id):
        now = int(time.time())
        proof = self.proofs.get(tx_id)
        if not proof:
            return False
        return now > proof["timestamp"] + self.ttl

    def invalidate_if_expired(self, tx_id):
        if self.check_expiry(tx_id):
            self.proofs[tx_id]["active"] = False
            return "invalidated"
        return "still active"

import time, schedule
from datetime import datetime

# === [1] AI 계약 자동 생성기 ===
def generate_contract(tx_data, conditions, expiry_hours=72):
    """
    tx_data 예시:
    {
        "sender": "alice",
        "receiver": "bob",
        "amount": 100,
        "coin": "USDT",
        "tx_id": "tx19z",
        "time": "2025-05-08 15:00"
    }
    """
    contract = {
        "contract_id": f"contract_{tx_data['tx_id']}",
        "parties": [tx_data["sender"], tx_data["receiver"]],
        "created_at": tx_data["time"],
        "expiry_hours": expiry_hours,
        "conditions": conditions,
        "proof_tx": tx_data["tx_id"],
        "status": "pending"
    }
    return contract

# === [2] 타임락 기반 자동 만료 확인 ===
def check_contract_expiry(contract, current_time_unix):
    contract_time = int(time.mktime(time.strptime(contract["created_at"], "%Y-%m-%d %H:%M")))
    return current_time_unix >= contract_time + contract["expiry_hours"] * 3600

# === [3] 조건 기반 자동 증거 해제 판단 ===
def evaluate_conditions(contract, confirmation_received=False, current_time=None):
    if confirmation_received:
        contract["status"] = "released"
        return "조건 승인 → 증거 공개"

    if current_time and check_contract_expiry(contract, current_time):
        contract["status"] = "released"
        return "시간 만료 → 증거 자동 공개"

    return "조건 미충족 → 대기"

# === [4] 자율 운영 스케줄러 설정 (설치형 기준) ===
def auto_trigger(contract):
    now = int(time.time())
    result = evaluate_conditions(contract, current_time=now)
    print(f"[{contract['contract_id']}] 상태: {result} | 현재 시간: {datetime.now().strftime('%H:%M:%S')}")

# === 예시 계약 데이터 ===
tx_data = {
    "sender": "alice",
    "receiver": "bob",
    "amount": 100,
    "coin": "USDT",
    "tx_id": "tx19z",
    "time": "2025-05-08 15:00"
}

conditions = ["수신자가 승인하면 증거 공개", "72시간 이내 이의 없음"]

# === 계약 생성 ===
contract = generate_contract(tx_data, conditions)

# === 스케줄링 설정 ===
schedule.every(10).seconds.do(auto_trigger, contract=contract)

# === 실행 루프 ===
if __name__ == "__main__":
    print(f"▶ 계약 [{contract['contract_id']}] 모니터링 시작")
    while True:
        schedule.run_pending()
        time.sleep(1)

import json, requests, qrcode

# === [1] 계약 JSON 생성 ===
def generate_contract(contract_id, sender, receiver, tx_id, conditions, expiry_hours=72):
    return {
        "contract_id": contract_id,
        "parties": [sender, receiver],
        "created_at": "2025-05-09 10:00",
        "expiry_hours": expiry_hours,
        "conditions": conditions,
        "proof_tx": tx_id,
        "status": "pending"
    }

# === [2] 계약 JSON → NFT 메타데이터 변환 ===
def contract_to_nft_metadata(contract_json, ipfs_hash):
    return {
        "name": f"Contract NFT - {contract_json['contract_id']}",
        "description": f"Smart contract between {contract_json['parties'][0]} and {contract_json['parties'][1]}",
        "external_url": f"https://ipfs.io/ipfs/{ipfs_hash}",
        "attributes": [
            {"trait_type": "Status", "value": contract_json["status"]},
            {"trait_type": "ExpiresIn", "value": f"{contract_json['expiry_hours']}h"},
            {"trait_type": "TX_ID", "value": contract_json["proof_tx"]}
        ]
    }

# === [3] 계약서 IPFS 업로드 (Pinata) ===
def upload_contract_to_ipfs(file_path, pinata_key, pinata_secret):
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": pinata_key,
        "pinata_secret_api_key": pinata_secret
    }
    with open(file_path, 'rb') as f:
        files = {"file": (file_path, f)}
        res = requests.post(url, files=files, headers=headers)
    return res.json()["IpfsHash"]

# === [4] 계약 QR코드 생성 ===
def generate_contract_qr(ipfs_hash, save_path="contract_qr.png"):
    url = f"https://ipfs.io/ipfs/{ipfs_hash}"
    img = qrcode.make(url)
    img.save(save_path)
    return save_path

# === [5] DAO 구조 정의 (가중치 투표 포함) ===
class ContractDAO:
    def __init__(self):
        self.contract_votes = {}
        self.weights = {}

    def set_weight(self, address, weight):
        self.weights[address] = weight

    def submit_contract(self, contract_id):
        self.contract_votes[contract_id] = {"yes": 0, "no": 0, "voted": set()}

    def vote(self, contract_id, address, support):
        if address in self.contract_votes[contract_id]["voted"]:
            return "already voted"
        weight = self.weights.get(address, 1)
        if support:
            self.contract_votes[contract_id]["yes"] += weight
        else:
            self.contract_votes[contract_id]["no"] += weight
        self.contract_votes[contract_id]["voted"].add(address)
        return "vote accepted"

    def result(self, contract_id):
        vote = self.contract_votes[contract_id]
        if vote["yes"] > vote["no"]:
            return "approved"
        elif vote["no"] > vote["yes"]:
            return "rejected"
        else:
            return "undecided"

import json, hashlib, time
from datetime import datetime

# === [1] AI 계약 자동 평가 시스템 ===
    def evaluate_contract_risk(contract):
        """
        리스크 점수는 100점 만점 기준. 리스크가 높을수록 점수 낮음.
        """
        score = 100
        if contract['expiry_hours'] >= 720:
            score -= 30
        if any("이의 없음" in c for c in contract['conditions']):
            score -= 20
        if abs(len(contract['parties']) - 2) > 0:
            score -= 10
        return score

# === [2] NFT 고유성 해시 생성 (Proof of Unique) ===
    def generate_proof_of_unique(contract_json):
        raw = json.dumps(contract_json, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode()).hexdigest()

# === [3] 자동 파기 타이머 체크 ===
    def check_and_trigger_selfdestruct(contract_json, now_unix=None):
        if now_unix is None:
            now_unix = int(time.time())
        created_at = time.mktime(time.strptime(contract_json["created_at"], "%Y-%m-%d %H:%M"))
        expiry_time = created_at + contract_json["expiry_hours"] * 3600
        if now_unix > expiry_time:
            return "SELFDESTRUCT_SIGNAL"
        return "active"

# === [4] 전체 실행 예시 ===
    if __name__ == "__main__":
    # 계약 예시
        contract = {
            "contract_id": "contract_tx21a",
            "parties": ["alice", "bob"],
            "created_at": "2025-05-10 12:00",
            "expiry_hours": 72,
            "conditions": ["이의 없음 시 유효", "72시간 초과 시 자동 폐기"],
            "proof_tx": "tx21a",
            "status": "pending"
            }

    # 1. 리스크 평가
    score = evaluate_contract_risk(contract)
    print("▶ 계약 리스크 점수:", score)

    # 2. 고유 해시 생성
    unique_hash = generate_proof_of_unique(contract)
    print("▶ 계약 PoU 해시:", unique_hash)

    # 3. 타임락 파기 조건 확인
    status = check_and_trigger_selfdestruct(contract)
    print("▶ 자동 파기 상태:", status)

# === [3] 계약 패키지 DAO 관리 시스템 ===
class ContractPackageDAO:
    def __init__(self):
        self.packages = {}
        self.index = set()  # 기존 계약 해시 저장소

    def register_package(self, package_id, contracts):
        hashes = [compute_contract_hash(c) for c in contracts]
        if any(h in self.index for h in hashes):
            return "중복 계약 포함됨"
        self.packages[package_id] = {
            "contracts": contracts,
            "hashes": hashes,
            "status": "pending"
        }
        self.index.update(hashes)
        return "등록 완료"

    def approve_package(self, package_id):
        if package_id in self.packages:
            self.packages[package_id]["status"] = "approved"

    def get_package_status(self, package_id):
        return self.packages.get(package_id, {}).get("status", "unknown")