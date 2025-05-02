# ZeroTalk 글로벌 설정 모듈 (5만 → 50억 확장형 구성)

import os
import platform
from datetime import datetime

# === 기본 앱 정보 ===
APP_NAME = "ZeroTalk"
APP_DESCRIPTION = "AI 기반 완전 자율형 메신저 플랫폼"
VERSION = "1.0.0"
DEVELOPER = "ZeroTech AI Division"
SUPPORT_EMAIL = "support@zerotalk.ai"

#  서버 설정
HOST = "0.0.0.0"
PORT = 5000
DEBUG_MODE = False
USE_HTTPS = False
MAX_CONNECTIONS = 50000
SOCKET_TIMEOUT = 30  # 초

# 시스템 자율 운영 설정
ENABLE_AUTO_BACKUP = True
BACKUP_INTERVAL_SECONDS = 600
BACKUP_PATH = "logs/backup/"
AUTO_CLEANUP_DAYS = 7
CLEANUP_ENABLED = True
MONITOR_INTERVAL_SECONDS = 10
ENABLE_MONITOR_BROADCAST = True
ENABLE_EMERGENCY_DETECTION = True

#  로그 및 경로
LOG_PATH = "logs/server.log"
ADMIN_LOG_PATH = "logs/admin_logs.json"
SYSTEM_STATUS_FILE = "logs/system_status.json"
SUMMARY_PATH = "logs/summary.json"
UPTIME_FILE = "logs/uptime.txt"

# 5. 데이터 저장소
DATABASE_TYPE = "sqlite"
DATABASE_PATH = "data/zerotalk.db"
TOKEN_FILE = "security/token_data.json"
SECURITY_FILE = "security/security_data.json"
DEVICE_LOG_FILE = "security/device_log.json"

# 메시지 설정
MESSAGE_MAX_LENGTH = 2000
MAX_FILE_SIZE_MB = 50
SUPPORTED_FILE_TYPES = ["jpg", "png", "gif", "mp3", "mp4", "pdf", "zip"]

# 채팅방 설정
MAX_DM_HISTORY = 1000
MAX_ROOM_HISTORY = 10000
ROOM_DEFAULT_CAPACITY = 50
ROOM_MAX_CAPACITY = 5000

# 워키토키 기능 설정
WALKIE_MODE_ENABLED = True
WALKIE_CHANNEL_TIMEOUT = 10  # 초단위
WALKIE_BROADCAST_PREFIX = "[음성]"

# 시스템 모니터링
MONITOR_INTERVAL = 10
MONITOR_LOG_PATH = "logs/system_status.json"
ENABLE_MONITOR_BROADCAST = True
MONITOR_CRITICAL_CPU = 90.0
MONITOR_CRITICAL_MEM = 90.0

# 유저 프로파일
USER_AVATAR_PATH = "user_data/avatars/"
DEFAULT_AVATAR = "default.png"
USER_DATA_PATH = "user_data/profiles/"
TOKEN_PATH = "user_data/tokens.json"

# 자동 토큰 정책
TOKEN_LENGTH = 12
TOKEN_ENCRYPT = True
TOKEN_REGENERATION_INTERVAL_DAYS = 90
ENABLE_TOKEN_ROTATION = True

# 관리자 옵션
DEFAULT_ADMIN_ID = "admin"
DEFAULT_ADMIN_PW = "admin1234"
ADMIN_CHANNEL_LOG = "logs/admin_channel.json"
BLOCKED_USERS_FILE = "blocked_users.json"
BLOCKED_IPS_FILE = "logs/blocked_ips.json"
ALLOWED_IPS_FILE = "logs/allowed_ips.json"


# IP 제한 정책
MAX_JOIN_PER_IP = 3
IP_BAN_DURATION_DAYS = 7
BLOCKED_IPS_FILE = "logs/blocked_ips.json"
ALLOWED_IPS_FILE = "logs/allowed_ips.json"

# 이메일 인증 설정
EMAIL_SMTP_SERVER = "smtp.example.com"
EMAIL_SMTP_PORT = 587
EMAIL_SENDER = "no-reply@zerotalk.ai"
EMAIL_SENDER_PASS = "your_password_here"
EMAIL_VERIFY_LIMIT = 5
EMAIL_RESEND_COOLDOWN = 180  # 초단위

# QR 보안 설정
MAX_FAILED_LOGIN = 5
BAN_DURATION_HOURS = 24
TOKEN_LENGTH = 12
TOKEN_EXPIRY_DAYS = 180
ENABLE_2FA = True
ENCRYPTION_KEY = "Z3r0T@lkEncryptionKey"
USE_FIREWALL = True

# AI 자동 응답 설정
AI_ASSISTANT_NAME = "보미"
AI_RESPONDER_ENABLED = True
AI_RESPONDER_COMMANDS = ["/도움", "/상태", "/비상"]
AI_LOG_PATH = "logs/ai_responder.json"
AI_CONTEXT_LIMIT = 3000

# 암호화 설정
ENCRYPTION_ENABLED = True
ENCRYPTION_KEY_PATH = "config/secret.key"
ENCRYPTION_ALGORITHM = "AES-256"

# 글로벌 다국어 설정
LANGUAGE_SUPPORTED = ["ko", "en", "ja", "zh", "vi", "th", "km", "tl"]
LANGUAGE_DEFAULT = "ko"
ENABLE_AUTO_TRANSLATION = True
AUTO_TRANSLATION_ENGINE = "google"

# 플랫폼 라이센스 및 정보
PLATFORM_NAME = "ZeroTalk"
PLATFORM_VERSION = "1.0.0-beta"
PLATFORM_UUID = "ztk-2025-main-prod"

# 로그 설정
ENABLE_LOG_ROTATION = True
MAX_LOG_SIZE_MB = 500
LOG_ROTATE_PATH = "logs/rotate/"
LOG_ARCHIVE_FORMAT = "zip"
ENABLE_LOG_ENCRYPTION = False

# 서버 상태 자동보고 설정
AUTO_STATUS_REPORT = True
STATUS_REPORT_INTERVAL = 600
STATUS_REPORT_WEBHOOK = "https://status.zerotalk.ai/report"

# 기타 예비 설정
DEBUG_MODE = False
ENABLE_FAKE_DELAY = False
FAKE_DELAY_RANGE = (0.2, 0.7)

# === 서버 환경 ===
HOST = "0.0.0.0"
PORT = 5000
USE_HTTPS = False
DEBUG = True
DEFAULT_LANGUAGE = "ko"

# === 파일/디렉토리 구조 ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DATA_DIR = os.path.join(BASE_DIR, "data")
BACKUP_DIR = os.path.join(LOG_DIR, "backup")
TOKEN_FILE = os.path.join(DATA_DIR, "token_data.json")
SECURITY_FILE = os.path.join(DATA_DIR, "security_data.json")

#  시스템 스위치 
USE_TOKEN_AUTH = True
ENABLE_EMAIL_RECOVERY = True
ALLOW_ANONYMOUS_USERS = False
ADMIN_MODE = True
ALLOW_VOICE_CHAT = True
ALLOW_FILE_TRANSFER = True
AUTO_BACKUP_ENABLED = True

#  보안 정책 
MIN_PASSWORD_LENGTH = 8
IP_BLOCK_THRESHOLD = 3
BLOCK_DURATION_DAYS = 7
ALLOW_MULTIPLE_DEVICES = False
ENCRYPT_TOKENS = True
USE_FIREWALL = True
VPN_BLOCK = False

#  토큰 설정 
TOKEN_LENGTH = 12
TOKEN_EXPIRY_DAYS = 180
TOKEN_HASH_METHOD = "sha256"

#  이메일 설정 
SMTP_SERVER = "smtp.zerotalk.ai"
SMTP_PORT = 587
SMTP_USER = "noreply@zerotalk.ai"
SMTP_PASSWORD = "ChangeThisSecurely"
SUPPORT_EMAIL = "support@zerotalk.ai"
EMAIL_LIMIT_PER_DAY = 5

#  로그 정책 
MAX_LOG_SIZE_MB = 500
LOG_ROTATION_ENABLED = True
LOG_FILE_NAME = "chat_log.json"
COMPRESS_LOG_AFTER_DAYS = 2
LOG_FORMAT = "json"

#   API 인증 / 버전관리
API_KEY_HEADER = "X-ZeroTalk-API-KEY"
API_VERSION = "v1"
ENABLE_API_RATE_LIMIT = True
MAX_REQUESTS_PER_MIN = 120
ENABLE_IP_TRACKING = True


#  자동화 알림 설정 
AUTO_ALERT_ADMIN_ON_HIGH_LOAD = True
ALERT_CPU_THRESHOLD = 90.0
ALERT_MEM_THRESHOLD = 90.0
ALERT_ON_DISK_USAGE = True

#  긴급 대응 모드 설정
EMERGENCY_CPU_THRESHOLD = 90.0
EMERGENCY_USER_THRESHOLD = 50000
EMERGENCY_LOG_PATH = "logs/emergency_mode.json"

# === 사용자 제한 설정 ===
MAX_ONLINE_USERS = 50000
DEFAULT_ROOM_CAPACITY = 1000
MAX_FILE_SIZE_MB = 30
MAX_MESSAGE_LENGTH = 2048

#  UI / 프론트 설정 
DEFAULT_THEME = "dark"
LANGUAGE_AUTO_DETECT = True
FONT_SIZE = 14
WELCOME_MESSAGE = "ZeroTalk에 오신 것을 환영합니다."

#  UI/UX 설정
ENABLE_DARK_MODE = True
DEFAULT_THEME = "dark"
FONT_FAMILY = "Arial"
FONT_SIZE = 12

# === AI 응답 전략 ===
AI_COMMAND_PREFIX = "/"
ALLOW_AI_CONVERSATION = True
ALLOW_AI_INSIDE_ROOMS = True
AI_RESPONDS_TO = ["상태", "차단", "복구", "진단", "공지"]
AI_NAME = "보미"
AI_VERSION = "1.0-ZT"
ALLOW_AI_EMOTION = False

# === 백엔드 운영자 정보 ===
SYSTEM_OWNER = "오빠"
DATACENTER_LOCATION = "Korea, GABIA"
START_TIMESTAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# === 외부 연동 API ===
GPT_API_KEY = "sk-xxx"
IPINFO_API = "https://ipinfo.io/json"
ENABLE_GPT_RELAY = False
ENABLE_TRANSLATION_API = False

# === 백업 정책 ===
BACKUP_FREQUENCY_MIN = 30
MAX_BACKUP_COUNT = 48
AUTO_DELETE_OLD_BACKUP = True

# === 채널 / 봇 통합 설정 ===
ENABLE_BOT_CHANNEL = True
BOT_CHANNEL_NAME = "보미드라이브"
ENABLE_EXTERNAL_CHANNELS = False
ALLOWED_CHANNELS = ["보미드라이브", "트랜스링크", "제로월렛"]

# 1. 프로젝트 루트 경로 자동 감지
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. 로그 디렉토리 설정
LOG_DIR = os.path.join(ROOT_DIR, "logs")
CHAT_LOG_DIR = os.path.join(LOG_DIR, "chats")
SYSTEM_LOG_DIR = os.path.join(LOG_DIR, "system")
BACKUP_DIR = os.path.join(LOG_DIR, "backup")

# 3. 최대 동시 접속자 설정 (향후 k8s 확장 대응)
MAX_ONLINE_USERS = 50000
MAX_ROOMS = 100000
MAX_MSG_SIZE = 2048  # bytes

# 4. 서버 네트워크 설정
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000
SOCKET_PORT = 5050
USE_HTTPS = False

# 5. 관리자 정보
ADMIN_EMAIL = "admin@zerotalk.ai"
SUPPORT_EMAIL = "support@zerotalk.ai"

# 6. 인증 제한
MAX_LOGIN_ATTEMPTS_PER_IP = 3
IP_BLOCK_DAYS = 7
EMAIL_REQUEST_LIMIT_PER_DAY = 5

# 7. 보안 설정
USE_TOKEN = True
TOKEN_LENGTH = 12
TOKEN_TIMEOUT_MIN = 5
ALLOW_TEMP_TOKEN = False

# 8. 이메일 인증 SMTP 정보 (보안상 .env 분리 가능)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "youremail@gmail.com"
SMTP_PASSWORD = "yourpassword"
EMAIL_SUBJECT = "ZeroTalk 인증 코드"

# 9. 파일 업로드 설정
FILE_UPLOAD_DIR = os.path.join(ROOT_DIR, "uploads")
ALLOWED_FILE_EXTENSIONS = [".jpg", ".png", ".pdf", ".txt", ".mp3", ".mp4"]
MAX_FILE_SIZE_MB = 50

# 10. 감시 키워드 필터링
BANNED_WORDS = ["fuck", "shit", "욕1", "욕2", "바보", "멍청이"]
BANNED_USERNAMES = ["admin", "root", "test", "관리자"]

# 11. 채팅방 정책
ROOM_EXPIRY_DAYS = 30
MAX_USERS_PER_ROOM = 300
ALLOW_ANONYMOUS_ROOM = False

# 12. API 인증키 (OAuth 또는 내부키)
API_KEY = "ZT-CORE-API-KEY-1234567890"
INTERNAL_SECRET = "ZT-INT-SECURE-KEY"

# 13. 상태 모니터링 설정
MONITOR_CPU_THRESHOLD = 90
MONITOR_MEM_THRESHOLD = 90
LOG_ROTATE_SIZE_MB = 500
BACKUP_CYCLE_MIN = 10

# 14. 백업 설정
AUTO_BACKUP_ENABLED = True
AUTO_CLEANUP_DAYS = 7

# 15. 관리자 채널
ADMIN_NOTICE_PATH = os.path.join(LOG_DIR, "admin_notice.json")
ADMIN_CHANNEL_LOG = os.path.join(LOG_DIR, "admin_channel.json")
EMERGENCY_LOG = os.path.join(LOG_DIR, "emergency_mode.json")
BLOCKED_USERS_FILE = os.path.join(LOG_DIR, "blocked_users.json")

# 16. DB 경로 설정
DATABASE_PATH = os.path.join(ROOT_DIR, "db", "zerotalk.db")
SQLITE_TIMEOUT = 30

# 17. 메시지 전송 정책
ENABLE_ENCRYPTION = True
MESSAGE_EXPIRY_DAYS = 90

# 18. 타임스탬프 생성 함수
    def current_time():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 19. 경로 초기화 함수
    def ensure_directories():
        for path in [LOG_DIR, CHAT_LOG_DIR, SYSTEM_LOG_DIR, BACKUP_DIR, FILE_UPLOAD_DIR]:
            os.makedirs(path, exist_ok=True)

# 20. 시스템 환경정보 출력 (디버그용)
    def print_config_summary():
        print("="*40)
        print("[ZeroTalk Config Loaded]")
        print(f"Root: {ROOT_DIR}")
        print(f"Logs: {LOG_DIR}")
        print(f"Max Online Users: {MAX_ONLINE_USERS}")
        print(f"Allow File Types: {ALLOWED_FILE_EXTENSIONS}")
        print(f"Token Usage: {USE_TOKEN}")
        print(f"Encryption: {ENABLE_ENCRYPTION}")
        print("="*40)

# --- 설정 초기화 실행 (import 시 자동 실행되게 구성)
    ensure_directories()
    print_config_summary()