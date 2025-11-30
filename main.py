import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


# Core Application Configuration
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable must be configured")

# Database Configuration
DB_PATH = "db/password_bot.db"

# Logging Configuration
LOG_PATH = "bot.log"

# Administrative Access Configuration
ADMIN_IDS = [123456789]  # Replace with actual administrator Telegram IDs


class SecurityConfig:
    """Security configuration settings for the password manager application."""
    
    # Session Management Settings
    SESSION_TIMEOUT = 180  # 3 minutes in seconds
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_TIMEOUT_WINDOW = 300  # 5 minutes in seconds
    
    # Rate Limiting Configuration
    MAX_REQUESTS_PER_MINUTE = 100
    MAX_PASSWORD_ENTRIES_PER_USER = 1000
    
    # Input Validation Parameters
    MAX_USERNAME_LENGTH = 50
    MIN_USERNAME_LENGTH = 3
    MAX_ENTRY_NAME_LENGTH = 100
    MIN_ENTRY_NAME_LENGTH = 2
    MAX_EMAIL_LENGTH = 254
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_LENGTH = 6
    
    # Encryption Security Settings
    ENCRYPTION_ALGORITHM = "AES"
    KEY_DERIVATION_ITERATIONS = 100000


# Global security configuration instance
security_config = SecurityConfig()