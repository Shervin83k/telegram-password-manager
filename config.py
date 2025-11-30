import os
from dotenv import load_dotenv

load_dotenv()

# Bot configuration
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is required")

# Database configuration
DB_PATH = "db/password_bot.db"

# Logging configuration
LOG_PATH = "bot.log"

# Session configuration
SESSION_TIMEOUT = 180  # 3 minutes in seconds

# Admin configuration (replace with your Telegram ID)
ADMIN_IDS = [123456789]  # Change this to your actual Telegram ID

# Encryption configuration
ENCRYPTION_SALT = b'password_saver_bot_salt'  # In production, use a random salt

# Security Configuration
class SecurityConfig:
    # Session security
    SESSION_TIMEOUT = 180  # 3 minutes
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_TIMEOUT_WINDOW = 300  # 5 minutes
    
    # Rate limiting
    MAX_REQUESTS_PER_MINUTE = 100
    MAX_PASSWORD_ENTRIES_PER_USER = 1000
    
    # Input validation limits
    MAX_USERNAME_LENGTH = 50
    MIN_USERNAME_LENGTH = 3
    MAX_ENTRY_NAME_LENGTH = 100
    MIN_ENTRY_NAME_LENGTH = 2
    MAX_EMAIL_LENGTH = 254
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_LENGTH = 6
    
    # Encryption security
    ENCRYPTION_ALGORITHM = "AES"
    KEY_DERIVATION_ITERATIONS = 100000
    
    # Security headers and flags
    ENABLE_CONTENT_SECURITY_POLICY = True
    ENABLE_STRICT_TRANSPORT_SECURITY = True

# Instantiate security config
security_config = SecurityConfig()