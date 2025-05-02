# ZeroTalk 초기화 모듈 (__init__.py)

import os
import sys
import json
import platform
import logging
import time
import psutil
import socket
import requests
import threading

from datetime import datetime
from googletrans import Translator

# 내부 모듈
from config import (
    APP_NAME, VERSION, LOG_PATH, ROOT_DIR, DATABASE_PATH,
    SUPPORT_EMAIL, MONITOR_INTERVAL, SYSTEM_STATUS_FILE, MAX_ONLINE_USERS
)

# 시스템 구성 모듈
import db
import admin
import monitoring
import security

# 디렉토리 생성 보장
for dir_ in ["logs", "data", "uploads"]:
    os.makedirs(dir_, exist_ok=True)

# 로그 설정
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# 시스템 부팅 로그 출력
    def startup_log():
        system = platform.uname()
        mem = psutil.virtual_memory().total // (1024**3)
        logging.info(f"{APP_NAME} v{VERSION} 기동")
        logging.info(f"OS: {system.system} {system.release} | CPU: {psutil.cpu_count()} | RAM: {mem}GB")
        print(f"▶ [{APP_NAME}] 시스템 부팅 완료")

# 서버 IP + 포트 로그
    def log_network_info():
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            logging.info(f"HOST: {hostname}, IP: {ip}")
        except:
            logging.warning("IP 확인 실패")

# 데이터베이스 연결 테스트
    def check_database():
        try:
            if not os.path.exists(DATABASE_PATH):
                with open(DATABASE_PATH, "w"): pass  # 빈 DB 파일 생성
            logging.info(f"데이터베이스 연결 확인: {DATABASE_PATH}")
            return True
        except Exception as e:
            logging.error(f"DB 연결 실패: {e}")
            return False

# 현재 상태 기록 저장
    def save_initial_status():
        status = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu": psutil.cpu_percent(),
            "mem": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "users_online": 0,  # 추후 채팅모듈과 연동
            "version": VERSION
            }
        with open(SYSTEM_STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=4)
        logging.info(f"시스템 상태 초기화 완료: {SYSTEM_STATUS_FILE}")

# 상태 출력
    def print_startup_summary():
        print("=" * 40)
        print(f"[{APP_NAME}] 시스템 구성 요약")
        print(f"버전: {VERSION}")
        print(f"DB 경로: {DATABASE_PATH}")
        print(f"운영자 이메일: {SUPPORT_EMAIL}")
        print(f"최대 동시 사용자: {MAX_ONLINE_USERS}")
        print("=" * 40)

# 전체 초기화 함수
    def initialize_core():
        startup_log()
        log_network_info()
        check_database()
        save_initial_status()
        print_startup_summary()

    # 어드민 시스템 시작
        admin.start_admin_monitor()

# 자동 실행
initialize_core()

# === 시스템 상태 초기 기록 저장 ===
    def save_system_snapshot():
        status = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "boot_check": True,
            "uptime": time.time()
            }
        with open("logs/boot_status.json", "w", encoding="utf-8") as f:
            json.dump(status, f, indent=4)
            print("[LOG] 부팅 상태 저장 완료")

# === 서버 기동 시간 기록 ===
    def record_start_time():
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("logs/boot_time.txt", "w", encoding="utf-8") as f:
            f.write(f"서버 시작 시각: {ts}")
        print(f"[LOG] 서버 시작 시각 기록됨 → {ts}")

# === 기본 구조 디렉토리 검사 ===
    def ensure_folder_structure():
        folders = [
            "logs", "logs/backup", "logs/chats",
            "user_data", "user_data/profiles", "user_data/avatars",
            "uploads", "security", "config", "db"
            ]
        for folder in folders:
            os.makedirs(folder, exist_ok=True)
        print("[BOOT] 폴더 구조 점검 완료")

# === 시스템 프로필 정보 수집 ===
    def show_platform_info():
        print("=" * 50)
        print("시스템 정보:")
        print(f"OS        : {platform.system()} {platform.release()}")
        print(f"Machine   : {platform.machine()}")
        print(f"Python    : {platform.python_version()}")
        print(f"CPU 개수  : {psutil.cpu_count()} 개")
        print(f"RAM 총용량: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB")
        print("=" * 50)

# === 실시간 사용자 수 모니터링 기록 ===
    def write_user_monitor_snapshot(user_count=0):
        snapshot = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "users_online": user_count,
            "cpu_now": psutil.cpu_percent(),
            "mem_now": psutil.virtual_memory().percent
            }
        with open("logs/live_users.json", "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=4)
        print("[SNAPSHOT] 사용자 상태 기록됨")

# === 서버 요약 로그 (짧은 보고) ===
    def write_summary_log():
        summary = {
            "boot_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "server_ready": True,
            "max_users": 50000,
            "version": "1.0.0-beta"
            }
        with open("logs/summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)
        print("[SUMMARY] 서버 요약 로그 저장")

# === 실행 (복불용 자동 흐름) ===
ensure_folder_structure()
record_start_time()
save_system_snapshot()
show_platform_info()
write_user_monitor_snapshot()
write_summary_log()

# === AI 응답 감시 로그 저장 ===
    def log_ai_interaction(user, prompt, response):
        log_path = "logs/ai_responder.json"
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": user,
            "prompt": prompt,
            "response": response
                }
        logs = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []
        logs.append(entry)
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)
        print(f"[AI] 로그 기록됨: {user} → {prompt[:20]}")

# === 네트워크 상태 진단 기록 ===
    def write_network_status():
        try:
            import urllib.request
            import socket

            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            external_ip = urllib.request.urlopen('https://api.ipify.org').read().decode()

            status = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hostname": hostname,
                "local_ip": local_ip,
                "external_ip": external_ip,
                "status": "reachable"
                }

            with open("logs/network_status.json", "w", encoding="utf-8") as f:
                json.dump(status, f, indent=4)

            print("[NET] 네트워크 상태 기록 완료")
        except Exception as e:
            print(f"[ERROR] 네트워크 상태 기록 실패: {e}")

# === 비상 모드 자동 감지 → 강제 전환 ===
    def auto_emergency_trigger():
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            if cpu > 90 or mem > 90:
                with open("logs/emergency_mode.json", "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now()} | CPU: {cpu}%, MEM: {mem}% → 비상 모드 감지\n")
                print("[EMERGENCY] 비상 모드 감지됨")
        except Exception as e:
            print(f"[EMERGENCY] 감지 실패: {e}")

# === 주기적 상태 점검 + 알림 로그 ===
    def periodic_status_check():
        print("[AI] 상태 감시 루프 실행됨")
        for i in range(3):
            auto_emergency_trigger()
            time.sleep(2)
        print("[AI] 간단 상태 감시 종료")

# === 자동 실행 블록 (4차 구성용 실행 흐름) ===
log_ai_interaction("시스템", "서버 재시작 확인", "정상 작동 중입니다.")
write_network_status()
periodic_status_check()

# === 시스템 진단 결과 분석 ===
    def run_self_diagnosis():
        results = {
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "log_status": "OK" if os.path.exists("logs/server.log") else "MISSING",
            "db_status": "OK" if os.path.exists("data/zerotalk.db") else "MISSING"
            }

        status = "PASS"
        if results["cpu"] > 90 or results["memory"] > 90:
            status = "WARN"
        if results["log_status"] == "MISSING" or results["db_status"] == "MISSING":
            status = "FAIL"

        print("[DIAGNOSIS] 시스템 자가진단 결과:", results)
        return {"status": status, "details": results}

# === 로그 자동 복구 기능 ===
    def recover_logs_if_needed():
        if not os.path.exists("logs/server.log"):
            with open("logs/server.log", "w", encoding="utf-8") as f:
                f.write(f"[{datetime.now()}] 로그 자동복구됨\n")
            print("[RECOVERY] server.log 파일이 재생성되었습니다.")

# === DB 자동 복구 기능 ===
    def recover_database_if_needed():
        db_path = "data/zerotalk.db"
        if not os.path.exists(db_path):
            with open(db_path, "w", encoding="utf-8") as f:
                f.write("")  # 최소 파일 구조
            print("[RECOVERY] DB 파일이 재생성되었습니다. (초기 상태)")

# === 서버 비정상 종료 로그 감지
    def detect_abnormal_shutdown():
        shutdown_flag = "logs/last_shutdown.ok"
        if not os.path.exists(shutdown_flag):
            print("[ALERT] 서버 비정상 종료 감지됨!")
            with open("logs/emergency_mode.json", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now()} | 서버 비정상 종료 → 긴급 감지됨\n")
            return True
        return False

# === 정상 종료 플래그 기록 (시스템 종료 전)
    def mark_normal_shutdown():
        with open("logs/last_shutdown.ok", "w", encoding="utf-8") as f:
            f.write(f"정상 종료: {datetime.now()}")

# === 5차 루틴 실행
print("[INIT-5] ZeroTalk 서버 진단 및 복구 루틴 실행 중...")
recover_logs_if_needed()
recover_database_if_needed()
    diagnosis_result = run_self_diagnosis()

    if detect_abnormal_shutdown():
        print("[INIT-5] 비상 복구 모드 전환 필요")
    else:
        print(f"[INIT-5] 서버 상태: {diagnosis_result['status']}")

# === 시스템 설정 실시간 로딩 ===
    def load_config_settings():
        config_path = os.path.join(BASE_DIR, "config.py")
        if not os.path.exists(config_path):
            print("[CONFIG] 설정 파일 누락됨. 기본값 사용")
            return {}

        config_globals = {}
        with open(config_path, "r", encoding="utf-8") as f:
            exec(f.read(), config_globals)
        print("[CONFIG] 설정 반영됨")
        return config_globals

# === 유저 활동 통계 추적 (간이 분석용)
USER_STATS_FILE = "logs/user_stats.json"

    def update_user_activity_stat(username):
        stats = {}
        if os.path.exists(USER_STATS_FILE):
            try:
                with open(USER_STATS_FILE, "r", encoding="utf-8") as f:
                    stats = json.load(f)
            except:
                stats = {}

        if username not in stats:
            stats[username] = {"messages": 0, "last_active": ""}

        stats[username]["messages"] += 1
        stats[username]["last_active"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(USER_STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=4, ensure_ascii=False)

# === AI 반응 감시 (GPT 감정/명령 로그 추출용)
AI_COMMAND_LOG = "logs/ai_command_log.json"

    def log_ai_command(username, command):
        entry = {
            "user": username,
            "command": command,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        logs = []
        if os.path.exists(AI_COMMAND_LOG):
            try:
                with open(AI_COMMAND_LOG, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []

        logs.append(entry)
        with open(AI_COMMAND_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)

# === 설정 불러오고 반영 실행
print("[INIT-6] config.py 실시간 설정 로딩 중...")
config = load_config_settings()

# config 변수에서 바로 사용 가능:
    if config.get("ENABLE_AI_RESPONDER"):
        print("[INIT-6] AI 응답 기능 활성화 상태입니다.")

    if config.get("MAX_ONLINE_USERS", 0) > 100000:
        print("[INIT-6] 고성능 대용량 모드입니다.")

# === GPT 서버 상태 점검 ===
GPT_PING_URL = "https://api.openai.com/v1/models"
GPT_STATUS_FILE = "logs/gpt_status.json"
GPT_PING_INTERVAL = 600  # 초

    def check_gpt_server():
        try:
            response = requests.get(GPT_PING_URL, timeout=5)
            status = "online" if response.status_code == 200 else "unstable"
        except:
            status = "offline"

        result = {
            "status": status,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        with open(GPT_STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"[GPT] 상태: {status}")

    def start_gpt_monitor():
        def loop():
            while True:
                check_gpt_server()
                time.sleep(GPT_PING_INTERVAL)
        threading.Thread(target=loop, daemon=True).start()

# === 감정 로그 정제 (AI 응답의 감정 라벨링용)
AI_EMOTION_LOG = "logs/ai_emotion_log.json"
POSITIVE_WORDS = ["고마워", "감사", "좋아", "사랑", "기쁨"]
NEGATIVE_WORDS = ["싫어", "짜증", "불편", "화나", "나빠"]

    def analyze_emotion(message):
        score = 0
        for word in POSITIVE_WORDS:
            if word in message:
                score += 1
        for word in NEGATIVE_WORDS:
            if word in message:
                score -= 1
        return "positive" if score > 0 else "negative" if score < 0 else "neutral"

    def log_emotion_analysis(username, message):
        emotion = analyze_emotion(message)
        entry = {
            "user": username,
            "emotion": emotion,
            "message": message,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        logs = []
        if os.path.exists(AI_EMOTION_LOG):
            try:
                with open(AI_EMOTION_LOG, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []
        logs.append(entry)
        with open(AI_EMOTION_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

# === 트래픽 응급 차단 시스템
TRAFFIC_ALERT_FILE = "logs/traffic_alert.json"
TRAFFIC_THRESHOLD_USERS = 50000
TRAFFIC_CHECK_INTERVAL = 30  # 초

    def traffic_emergency_check():
        while True:
            try:
                user_count = len(globals().get("connected_users", {}))
                if user_count > TRAFFIC_THRESHOLD_USERS:
                    alert = {
                        "status": "critical",
                        "active_users": user_count,
                        "triggered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                    with open(TRAFFIC_ALERT_FILE, "w", encoding="utf-8") as f:
                        json.dump(alert, f, indent=4)
                    print(f"[EMERGENCY] 동시접속 {user_count}명 초과 – 긴급 차단 조치 필요")
            except Exception as e:
                print(f"[TRAFFIC] 체크 오류: {e}")
            time.sleep(TRAFFIC_CHECK_INTERVAL)

    def start_traffic_guard():
        threading.Thread(target=traffic_emergency_check, daemon=True).start()

# === 실시간 번역 시스템 ===
LANG_CACHE_FILE = "logs/lang_cache.json"
translator = Translator()

    def translate_text(text, src="auto", dest="ko"):
        try:
            result = translator.translate(text, src=src, dest=dest)
            return result.text
        except Exception as e:
            print(f"[TRANSLATE] 실패: {e}")
            return text
    
    def cache_translation(original, translated, lang_from, lang_to):
        cache = {}
        if os.path.exists(LANG_CACHE_FILE):
            try:
                with open(LANG_CACHE_FILE, "r", encoding="utf-8") as f:
                    cache = json.load(f)
            except:
                pass
        cache_key = f"{lang_from}|{lang_to}|{original}"
        cache[cache_key] = translated
        with open(LANG_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4)

# === AI 요약 로그 시스템 (최근 대화 요약 캐시)
SUMMARY_LOG_FILE = "logs/ai_summary.json"
SUMMARY_TRIGGER = 20  # 20 메시지마다 요약

summary_cache = []

    def add_to_summary_log(user, message):
        global summary_cache
        summary_cache.append(f"{user}: {message}")
        if len(summary_cache) >= SUMMARY_TRIGGER:
            summary_text = summarize_messages(summary_cache)
            save_summary(summary_text)
            summary_cache = []
    def summarize_messages(messages):
# 매우 간단한 요약 방식 (GPT API 연동 가능)
        if not messages:
            return ""
        summary = messages[0]
        if len(messages) > 1:
            summary += f" ... ({len(messages)}줄 생략)"
        return summary

    def save_summary(summary):
        if not summary:
            return
        entry = {
            "summary": summary,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        summaries = []
        if os.path.exists(SUMMARY_LOG_FILE):
            try:
                with open(SUMMARY_LOG_FILE, "r", encoding="utf-8") as f:
                    summaries = json.load(f)
            except:
                pass
        summaries.append(entry)
        with open(SUMMARY_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=4)
        print(f"[SUMMARY] 저장됨: {summary}")

# === 서버 사용량 기반 자동 셧다운 트리거 ===
SHUTDOWN_FLAG_FILE = "logs/shutdown_flag.json"
MAX_CPU = 95
MAX_MEM = 95
MAX_USERS = 80000

    def auto_shutdown_trigger():
        while True:
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                users = len(globals().get("connected_users", {}))
                if cpu > MAX_CPU or mem > MAX_MEM or users > MAX_USERS:
                    with open(SHUTDOWN_FLAG_FILE, "w", encoding="utf-8") as f:
                        json.dump({
                            "triggered": True,
                            "cpu": cpu,
                            "mem": mem,
                            "users": users,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }, f, indent=4)
                    print(f"[AUTO-SHUTDOWN] 조건 초과 → 서버 중단 플래그 설정됨")
            except Exception as e:
                print(f"[AUTO-SHUTDOWN] 에러: {e}")
            time.sleep(15)

threading.Thread(target=auto_shutdown_trigger, daemon=True).start()
print("[INIT-8] 다국어 번역, 요약 시스템, 자동 셧다운 트리거 작동 중")

# === 인증 캐시 시스템 (IP, 이메일, 토큰) ===
AUTH_CACHE_FILE = "logs/auth_cache.json"

    def load_auth_cache():
        if not os.path.exists(AUTH_CACHE_FILE):
            return {}
        try:
            with open(AUTH_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
        except:
            return {}
        
    def update_auth_cache(username, ip, email=None, token=None):
        cache = load_auth_cache()
        cache[username] = {
            "ip": ip,
            "email": email,
            "token": token,
            "last_login": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        with open(AUTH_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4)

    def is_token_valid(username, token_input):
        cache = load_auth_cache()
        user_data = cache.get(username)
        if not user_data:
            return False
        return user_data.get("token") == token_input

    def get_last_ip(username):
        cache = load_auth_cache()
        return cache.get(username, {}).get("ip", None)

# === 운영 상태 조합 로그 생성기 ===
STATUS_COMBINED_LOG = "logs/status_combined.json"

    def generate_combined_status():
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent
            uptime = round(time.time() - server_start_time)
            users = len(globals().get("connected_users", {}))

            result = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "cpu": cpu,
                "memory": mem,
                "disk": disk,
                "users_online": users,
                "uptime_sec": uptime,
                "emergency": emergency_mode
            }

            with open(STATUS_COMBINED_LOG, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=4)
            print("[STATUS] 종합 상태 로그 갱신 완료")
        except Exception as e:
            print(f"[STATUS ERROR] 조합 실패: {e}")

# === 서버 재시작 복구용 캐시 시스템 ===
RECOVERY_CACHE = "logs/recovery_cache.json"

    def save_recovery_point():
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "connected_users": list(globals().get("connected_users", {}).keys()),
            "active_rooms": list(globals().get("room_members", {}).keys()),
            }
        with open(RECOVERY_CACHE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print("[RECOVERY] 복구 지점 저장됨")

    def load_recovery_point():
        if not os.path.exists(RECOVERY_CACHE):
            print("[RECOVERY] 복구 캐시 없음")
            return
        try:
            with open(RECOVERY_CACHE, "r", encoding="utf-8") as f:
                data = json.load(f)
                print("[RECOVERY] 복구 정보:", data)
                # 실제 연결 복구는 socket 레이어에서 재연결시 자동 처리
        except Exception as e:
            print(f"[RECOVERY ERROR] 불러오기 실패: {e}")

threading.Thread(target=generate_combined_status, daemon=True).start()
threading.Thread(target=save_recovery_point, daemon=True).start()
print("[INIT-9] 인증 캐시 + 복구 캐시 + 상태 시각화 조합 작동 중")

    ZeroTalk system_init.py (import 없이, 초기화 전용 구성)

# === 시스템 상태 전역 변수 ===
system_ready = False
emergency_flag = False
startup_timestamp = None
system_warnings = []
connected_clients = {}
connected_rooms = {}
startup_checks_passed = True
cpu_usage = 0.0
mem_usage = 0.0
disk_usage = 0.0
active_threads = []
log_rotation_enabled = True
current_log_index = 1
emergency_log_triggered = False
backup_schedule_enabled = True
backup_paths = []
temp_cleanup_enabled = True
system_signature = "ZT-SYS-CORE-V1.0"
allowed_languages = ["ko", "en", "ja", "zh"]

# === 시스템 이벤트 기록 ===
event_log = []

    def log_event(event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_log.append({"time": timestamp, "event": event})


# === 시스템 헬스체크 ===
    def perform_health_check():
        global cpu_usage, mem_usage, disk_usage, system_warnings
        try:
            cpu_usage = psutil.cpu_percent()
            mem_usage = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage("/").percent

            if cpu_usage > 90:
                system_warnings.append("[WARN] CPU 사용률 과다")
            if mem_usage > 90:
                system_warnings.append("[WARN] 메모리 사용률 과다")
            if disk_usage > 90:
                system_warnings.append("[WARN] 디스크 사용률 과다")

            log_event(f"헬스체크 완료 | CPU: {cpu_usage}%, MEM: {mem_usage}%, DISK: {disk_usage}%")
            return True
        except Exception as e:
            log_event(f"[ERROR] 시스템 헬스체크 실패: {str(e)}")
            return False
    
# === 시스템 초기화 === #
    def initialize_system():
        global system_ready, startup_timestamp
        log_event("ZeroTalk 시스템 초기화 시작")
        startup_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = perform_health_check()
        system_ready = status
        if status:
            log_event("시스템 초기화 성공")
        else:
            log_event("[ERROR] 시스템 초기화 실패")
        return status
    
# === 자동 백업 스케줄러 등록 ===
    def register_backup_path(path):
        if path not in backup_paths:
            backup_paths.append(path)
            log_event(f"백업 경로 등록됨: {path}")


# === 임시 파일 정리 ===
    def cleanup_temp_files(target_dir, age_minutes=60):
        count = 0
        for root, _, files in os.walk(target_dir):
            for f in files:
                full_path = os.path.join(root, f)
                try:
                    last_modified = os.path.getmtime(full_path)
                    if time.time() - last_modified > age_minutes * 60:
                        os.remove(full_path)
                        count += 1
                except:
                    continue
        log_event(f"임시 파일 정리 완료: {count}개 삭제됨")

# === 긴급 모드 진입 ===
    def enter_emergency_mode(reason):
        global emergency_flag, emergency_log_triggered
        emergency_flag = True
        emergency_log_triggered = True
        log_event(f"[EMERGENCY] 비상 모드 진입: {reason}")

# === 긴급 모드 해제 ===
    def exit_emergency_mode():
        global emergency_flag
        emergency_flag = False
        log_event("[EMERGENCY] 비상 모드 해제")

# === 로그 요약 ===
    def summarize_logs():
        summary = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu": cpu_usage,
            "memory": mem_usage,
            "disk": disk_usage,
            "clients": len(connected_clients),
            "rooms": len(connected_rooms),
            "warnings": len(system_warnings),
            "status": "정상" if system_ready else "오류 있음"
            }
        return summary
    
# === 시스템 전체 상태 반환 ===
    def get_system_status():
        return {
            "uptime": (datetime.now() - datetime.strptime(startup_timestamp, "%Y-%m-%d %H:%M:%S")).seconds,
            "status": "READY" if system_ready else "ERROR",
            "cpu": cpu_usage,
            "mem": mem_usage,
            "disk": disk_usage,
            "emergency": emergency_flag,
            "signature": system_signature
            }
    
# === 진입점 함수 ===
    def start_system_monitoring():
        initialize_system()
        threading.Thread(target=monitor_loop, daemon=True).start()
        log_event("[INIT] 시스템 모니터링 루프 시작됨")

# === 모니터 루프 ===
    def monitor_loop():
        while True:
            perform_health_check()
            if cpu_usage > 95 or mem_usage > 95:
                enter_emergency_mode("시스템 과부하")
            time.sleep(10)

# === 외부 출력용 ===
    def export_system_log():
        return {
            "log": event_log[-100:],
            "warnings": system_warnings[-20:],
            "status": summarize_logs()
            }