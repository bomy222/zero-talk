import os
import json
import sqlite3
import time

from datetime import datetime

DB_PATH = "data/zerotalk.db"
USER_LOG_PATH = "logs/user_stats.json"
CHAT_EXPORT_PATH = "logs/exported_chats.json"
SYSTEM_EVENT_LOG = "logs/system_events.json"
BACKUP_RECORD_LOG = "logs/backup_history.json"
AI_RESPONSE_LOG = "logs/ai_response.json"
TRANSLATION_LOG = "logs/translation_records.json"
FILE_UPLOAD_LOG = "logs/file_uploads.json

    def connect():
        return sqlite3.connect(DB_PATH, check_same_thread=False)

# === DB 초기화 ===
    def initialize_db():
        conn = connect()
        cur = conn.cursor()

    # 유저 테이블
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                password TEXT,
                email TEXT,
                phone TEXT,
                token TEXT,
                registered_at TEXT
                )
            """)

    # 개인 메시지 로그
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                message TEXT,
                timestamp TEXT
                )
            """)

    # 단체방 정보
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                name TEXT PRIMARY KEY,
                created_by TEXT,
                created_at TEXT
                )
            """)

    # 단체방 메시지 로그
        cur.execute("""
            CREATE TABLE IF NOT EXISTS room_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT,
                sender TEXT,
                message TEXT,
                timestamp TEXT
                )
            """)

    # 로그인 로그
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                ip TEXT,
                device TEXT,
                login_time TEXT
                )
            """)

    conn.commit()
    conn.close()

# === 유저 등록 ===
    def register_user(id_, password, email="", phone="", token=""):
        conn = connect()
        cur = conn.cursor()
        cur.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", (
        id_, password, email, phone, token, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()

# === 유저 조회 ===
    def get_user_by_id(id_):
        conn = connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (id_,))
        row = cur.fetchone()
        conn.close()
        return row

# === 메시지 저장 ===
    def save_dm(sender, receiver, message):
        conn = connect()
        cur = conn.cursor()
        cur.execute("INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)", (
            sender, receiver, message, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()

# === DM 조회 ===
    def get_dm(sender, receiver, limit=100):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT sender, message, timestamp
            FROM messages
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
            ORDER BY id DESC
            LIMIT ?
        """, (sender, receiver, receiver, sender, limit))
        rows = cur.fetchall()
        conn.close()
        return rows[::-1]  # 최신순 정렬 후 역순으로

# === 단톡 메시지 저장 ===
    def save_room_message(room, sender, message):
        conn = connect()
        cur = conn.cursor()
        cur.execute("INSERT INTO room_messages (room, sender, message, timestamp) VALUES (?, ?, ?, ?)", (
            room, sender, message, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()

# === 단톡 메시지 불러오기 ===
    def get_room_messages(room, limit=200):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT sender, message, timestamp
            FROM room_messages
            WHERE room = ?
            ORDER BY id DESC
            LIMIT ?
        """, (room, limit))
        rows = cur.fetchall()
        conn.close()
        return rows[::-1]

# === 로그인 로그 기록 ===
    def log_login(user_id, ip, device):
        conn = connect()
        cur = conn.cursor()
        cur.execute("INSERT INTO login_logs (user_id, ip, device, login_time) VALUES (?, ?, ?, ?)", (
            user_id, ip, device, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
        conn.commit()
        conn.close()

# === 신고 테이블 ===
    def create_report_table():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter TEXT,
                reported TEXT,
                reason TEXT,
                message TEXT,
                timestamp TEXT
            )
            """)
        conn.commit()
        conn.close()

# === 차단 테이블 ===
    def create_block_table():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blocked_user TEXT,
                blocked_by TEXT,
                reason TEXT,
                timestamp TEXT
            )
            """)
        conn.commit()
        conn.close()

# === 채널 등록 테이블 ===
    def create_channel_table():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                name TEXT PRIMARY KEY,
                creator TEXT,
                created_at TEXT,
                is_private INTEGER DEFAULT 0
            )
            """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS channel_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT,
                sender TEXT,
                message TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

# === AI 로그 기록 ===
    def create_ai_log_table():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ai_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                prompt TEXT,
                response TEXT,
               timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

# === 백업 기록 ===
    def create_backup_table():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS backups (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_file TEXT,
                status TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

# === 토큰 기록 테이블 (히스토리 관리) ===
    def create_token_history_table():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS token_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                token TEXT,
                issued_at TEXT,
                expired_at TEXT
            )
        """)
        conn.commit()
        conn.close()

# === 초기 테이블 전체 생성 ===
    def initialize_extended_tables():
        create_report_table()
        create_block_table()
        create_channel_table()
        create_ai_log_table()
        create_backup_table()
        create_token_history_table()

# === 신고 등록 ===
    def insert_report(reporter, reported, reason, message, timestamp):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (reporter, reported, reason, message, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (reporter, reported, reason, message, timestamp))
        conn.commit()
        conn.close()

# === 차단 등록 ===
    def insert_block(blocked_user, blocked_by, reason, timestamp):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO blocked (blocked_user, blocked_by, reason, timestamp)
            VALUES (?, ?, ?, ?)
        """, (blocked_user, blocked_by, reason, timestamp))
        conn.commit()
        conn.close()

# === 채널 메시지 저장 ===
    def insert_channel_message(channel, sender, message, timestamp):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO channel_messages (channel, sender, message, timestamp)
            VALUES (?, ?, ?, ?)
        """, (channel, sender, message, timestamp))
        conn.commit()
        conn.close()

# === 채널 메시지 불러오기 ===
    def get_channel_messages(channel, limit=50):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT sender, message, timestamp
            FROM channel_messages
            WHERE channel = ?
            ORDER BY id DESC
           LIMIT ?
        """, (channel, limit))
        rows = cur.fetchall()
        conn.close()
        return rows[::-1]

# === AI 응답 로그 저장 ===
    def insert_ai_log(user, prompt, response, timestamp):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO ai_logs (user, prompt, response, timestamp)
            VALUES (?, ?, ?, ?)
        """, (user, prompt, response, timestamp))
        conn.commit()
        conn.close()

# === 백업 기록 저장 ===
    def insert_backup_log(backup_file, status, timestamp):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO backups (backup_file, status, timestamp)
            VALUES (?, ?, ?)
        """, (backup_file, status, timestamp))
        conn.commit()
        conn.close()

# === 토큰 히스토리 저장 ===
    def insert_token_history(user, token, issued_at, expired_at):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO token_history (user, token, issued_at, expired_at)
            VALUES (?, ?, ?, ?)
        """, (user, token, issued_at, expired_at))
        conn.commit()
        conn.close()

# === 특정 유저 차단 여부 확인 ===
    def is_user_blocked(username):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT 1 FROM blocked
            WHERE blocked_user = ?
            ORDER BY id DESC LIMIT 1
        """, (username,))
        result = cur.fetchone()
        conn.close()
        return result is not None

# === 신고 목록 가져오기 (관리자용)
    def get_reports(limit=100):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT reporter, reported, reason, message, timestamp
            FROM reports
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

# === 채널 메시지 삭제 (관리자 또는 유효기간 만료 시)
    def delete_channel_messages(channel, before_timestamp):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM channel_messages
            WHERE channel = ? AND timestamp < ?
        """, (channel, before_timestamp))
        conn.commit()
        conn.close()

# === AI 로그 목록 가져오기
    def get_ai_logs(limit=100):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT user, prompt, response, timestamp
            FROM ai_logs
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

# === 백업 기록 리스트 가져오기
    def get_backup_logs(limit=50):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT backup_file, status, timestamp
            FROM backups
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

# === 사용자별 토큰 히스토리 조회
    def get_token_history(user):
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT token, issued_at, expired_at
            FROM token_history
            WHERE user = ?
            ORDER BY id DESC
        """, (user,))
        rows = cur.fetchall()
        conn.close()
        return rows
"
os.makedirs("data", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# === DB 연결 ===
    def connect():
        return sqlite3.connect(DB_PATH, timeout=10)

# === 초기 테이블 생성 ===
    def init_db():
        conn = connect()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT,
                token TEXT,
                last_login TEXT
            )
            """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                message TEXT,
                timestamp TEXT
            )
            """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                name TEXT PRIMARY KEY,
                created_at TEXT,
                creator TEXT
            )
            """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                type TEXT,
                content TEXT,
                created_at TEXT
            )
            """)
        conn.commit()
        conn.close()

# === 사용자 등록 ===
    def register_user(user_id, email, token):
        conn = connect()
        cur = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            INSERT OR REPLACE INTO users (id, email, token, last_login)
            VALUES (?, ?, ?, ?)
            """, (user_id, email, token, now))
        conn.commit()
        conn.close()

# === 메시지 저장 ===
    def save_message(sender, receiver, msg):
        conn = connect()
        cur = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            INSERT INTO messages (sender, receiver, message, timestamp)
            VALUES (?, ?, ?, ?)
            """, (sender, receiver, msg, now))
        conn.commit()
        conn.close()

# === 방 생성 기록 ===
    def create_room(name, creator):
        conn = connect()
        cur = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            INSERT OR IGNORE INTO rooms (name, created_at, creator)
            VALUES (?, ?, ?)
            """, (name, now, creator))
        conn.commit()
        conn.close()

# === 시스템 로그 기록 ===
    def write_system_log(entry_type, content):
        conn = connect()
        cur = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            INSERT INTO logs (type, content, created_at)
            VALUES (?, ?, ?)
            """, (entry_type, content, now))
        conn.commit()
        conn.close()

# === 채팅 데이터 내보내기 ===
    def export_chats():
        conn = connect()
        cur = conn.cursor()
        cur.execute("SELECT sender, receiver, message, timestamp FROM messages")
        rows = cur.fetchall()
        conn.close()
        data = [{
            "sender": r[0],
            "receiver": r[1],
            "message": r[2],
            "timestamp": r[3]
            } for r in rows]
        with open(CHAT_EXPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return len(data)

# === 유저 활동 통계 ===
    def update_user_stat(user_id):
        stats = {}
        if os.path.exists(USER_LOG_PATH):
            with open(USER_LOG_PATH, "r", encoding="utf-8") as f:
                try:
                    stats = json.load(f)
                except:
                    stats = {}
        if user_id not in stats:
            stats[user_id] = {"messages": 0, "last_active": ""}
        stats[user_id]["messages"] += 1
        stats[user_id]["last_active"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(USER_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=4)

# === AI 응답 로그 저장 ===
    def save_ai_response(user, prompt, reply):
        log = {
            "user": user,
            "prompt": prompt,
            "response": reply,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        logs = []
        if os.path.exists(AI_RESPONSE_LOG):
            with open(AI_RESPONSE_LOG, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append(log)
        with open(AI_RESPONSE_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

# === 번역 기록 저장 ===
    def log_translation(text, translated, src, dst):
        record = {
            "original": text,
            "translated": translated,
            "source": src,
            "target": dst,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        logs = []
        if os.path.exists(TRANSLATION_LOG):
            with open(TRANSLATION_LOG, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append(record)
        with open(TRANSLATION_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

# === 파일 업로드 기록 ===
    def log_file_upload(user, filename):
        record = {
            "user": user,
            "filename": filename,
            "uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        logs = []
        if os.path.exists(FILE_UPLOAD_LOG):
            with open(FILE_UPLOAD_LOG, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append(record)
        with open(FILE_UPLOAD_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

# === 백업 이력 기록 ===
    def log_backup_file(filename):
        record = {
            "file": filename,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        logs = []
        if os.path.exists(BACKUP_RECORD_LOG):
            with open(BACKUP_RECORD_LOG, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append(record)
        with open(BACKUP_RECORD_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

# ZeroTalk db.py - 7차 확장: 신고, 제재, 통계 기능 포함

DB_ROOT = "db"
USER_DB = os.path.join(DB_ROOT, "users.json")
REPORT_DB = os.path.join(DB_ROOT, "reports.json")
MESSAGE_DB = os.path.join(DB_ROOT, "messages.json")
STATS_DB = os.path.join(DB_ROOT, "chat_stats.json")

os.makedirs(DB_ROOT, exist_ok=True)

# === 기본 JSON 로드 / 저장 ===
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
            json.dump(data, f, ensure_ascii=False, indent=4)

# === 1. 유저 신고 처리 ===
    def report_user(reporter, target, reason):
        reports = load_json(REPORT_DB)
        if target not in reports:
            reports[target] = []
        reports[target].append({
            "reporter": reporter,
            "reason": reason,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        save_json(REPORT_DB, reports)
        return True

# === 2. 신고 누적 검사 ===
    def check_report_count(username, threshold=3):
        reports = load_json(REPORT_DB)
        return len(reports.get(username, [])) >= threshold

# === 3. 자동 정지 대상 조회 ===
    def get_banned_users(threshold=3):
        reports = load_json(REPORT_DB)
        return [u for u, r in reports.items() if len(r) >= threshold]

# === 4. 메시지 최근 검색 (방별) ===
    def get_recent_messages(room_id, count=50):
        data = load_json(MESSAGE_DB)
        return data.get(room_id, [])[-count:]

# === 5. 유저 채팅 통계 기록 ===
    def record_chat_stat(username):
        stats = load_json(STATS_DB)
        if username not in stats:
            stats[username] = {"messages": 0}
        stats[username]["messages"] += 1
        save_json(STATS_DB, stats)

# === 6. 메시지 삭제 처리 ===
    def delete_message(room_id, timestamp):
        data = load_json(MESSAGE_DB)
        if room_id not in data:
            return False
        filtered = [m for m in data[room_id] if m["timestamp"] != timestamp]
        data[room_id] = filtered
        save_json(MESSAGE_DB, data)
        return True

# === 7. 메시지 복원 처리 (백업 활용) ===
    def restore_deleted_message(room_id, message_data):
        data = load_json(MESSAGE_DB)
        if room_id not in data:
            data[room_id] = []
        data[room_id].append(message_data)
        save_json(MESSAGE_DB, data)
        return True

# === 8. 관리자 로그 검색 ===
    def admin_search_messages(keyword, limit=100):
        data = load_json(MESSAGE_DB)
        result = []
        for room_id, logs in data.items():
            for msg in logs:
                if keyword in msg.get("message", ""):
                    result.append({**msg, "room": room_id})
                    if len(result) >= limit:
                        return result
        return result

# === 기본 설정 ===
DB_ROOT = "db"
EVENT_LOG_DB = os.path.join(DB_ROOT, "event_log.json")
USAGE_STATS_DB = os.path.join(DB_ROOT, "usage_stats.json")
BACKUP_DB_PATH = os.path.join(DB_ROOT, "backups")

os.makedirs(DB_ROOT, exist_ok=True)
os.makedirs(BACKUP_DB_PATH, exist_ok=True)

# === 공통 JSON 입출력 ===
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

# === 1. 이벤트 기록 (접속, 전송, 오류 등) ===
    def log_event(event_type, data):
        logs = load_json(EVENT_LOG_DB)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"type": event_type, "data": data, "time": timestamp}
        if "events" not in logs:
            logs["events"] = []
        logs["events"].append(entry)
        save_json(EVENT_LOG_DB, logs)

# === 2. 통계 기록: 일간 기준 ===
    def update_daily_usage(username):
        stats = load_json(USAGE_STATS_DB)
        today = datetime.now().strftime("%Y-%m-%d")
        if today not in stats:
            stats[today] = {}
        if username not in stats[today]:
            stats[today][username] = 0
        stats[today][username] += 1
        save_json(USAGE_STATS_DB, stats)

# === 3. 사용자 활동 순위 ===
    def get_top_users(date_str=None, limit=10):
        stats = load_json(USAGE_STATS_DB)
        if not date_str:
            date_str = datetime.now().strftime("%Y-%m-%d")
        day_stats = stats.get(date_str, {})
        ranked = sorted(day_stats.items(), key=lambda x: x[1], reverse=True)
        return ranked[:limit]

# === 4. DB 자동 백업 ===
    def auto_backup(db_name):
        db_path = os.path.join(DB_ROOT, db_name)
        if not os.path.exists(db_path):
            return False
        backup_name = f"{db_name.replace('.json', '')}_{int(time.time())}.bak"
        backup_path = os.path.join(BACKUP_DB_PATH, backup_name)
        with open(db_path, "r", encoding="utf-8") as src, open(backup_path, "w", encoding="utf-8") as dest:
            dest.write(src.read())
        return True

# === 5. 백업 목록 조회 ===
    def list_backups():
        return [f for f in os.listdir(BACKUP_DB_PATH) if f.endswith(".bak")]

# === 6. 최근 이벤트 로그 조회 ===
    def get_recent_events(limit=50):
        logs = load_json(EVENT_LOG_DB)
        return logs.get("events", [])[-limit:]

# === 7. 최근 일주일 통계 요약 ===
    def get_weekly_summary():
        stats = load_json(USAGE_STATS_DB)
        result = {}
        for date_str, day in list(stats.items())[-7:]:
            result[date_str] = sum(day.values())
        return result

# === 8. 유저별 누적 활동량 ===
    def get_user_totals():
        stats = load_json(USAGE_STATS_DB)
        totals = {}
        for day in stats.values():
            for user, count in day.items():
            totals[user] = totals.get(user, 0) + count
        return dict(sorted(totals.items(), key=lambda x: x[1], reverse=True))

# === 9. 이벤트별 카운트 통계 ===
    def get_event_counts():
        logs = load_json(EVENT_LOG_DB)
        result = {}
        for entry in logs.get("events", []):
            t = entry.get("type", "unknown")
            result[t] = result.get(t, 0) + 1
        return result