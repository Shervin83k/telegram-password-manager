import logging
import traceback
from typing import Optional, Dict, Any
from aiogram import types
from aiogram.fsm.context import FSMContext

logger = logging.getLogger(__name__)


class ErrorHandler:
    """Centralized error handling for security and user experience."""
    
    @staticmethod
    async def handle_auth_error(message: types.Message, state: FSMContext, error: Exception, context: str = ""):
        """Handle authentication-related errors."""
        error_id = ErrorHandler._generate_error_id()
        logger.error(f"Authentication error [{error_id}] in {context}: {error}")
        
        await state.clear()
        await message.answer("🔐 Authentication error. Please use /start to begin again.")
        
        return error_id
    
    @staticmethod
    async def handle_encryption_error(message: types.Message, state: FSMContext, error: Exception, context: str = ""):
        """Handle encryption-related errors."""
        error_id = ErrorHandler._generate_error_id()
        logger.error(f"Encryption error [{error_id}] in {context}: {error}")
        
        user_message = (
            "🔒 Encryption error occurred. Possible causes:\n"
            "• Invalid encryption key provided\n"
            "• Data corruption detected\n"
            "• Please verify your key and try again"
        )
        await message.answer(user_message)
        
        return error_id
    
    @staticmethod
    async def handle_database_error(message: types.Message, state: FSMContext, error: Exception, context: str = ""):
        """Handle database-related errors."""
        error_id = ErrorHandler._generate_error_id()
        logger.error(f"Database error [{error_id}] in {context}: {error}")
        
        await message.answer("💾 Storage system error. Please try again shortly.")
        
        return error_id
    
    @staticmethod
    async def handle_input_error(message: types.Message, state: FSMContext, error: Exception, context: str = ""):
        """Handle input validation errors."""
        error_id = ErrorHandler._generate_error_id()
        logger.warning(f"Input validation error [{error_id}] in {context}: {error}")
        
        await message.answer("📝 Invalid input provided. Please verify your data and try again.")
        
        return error_id
    
    @staticmethod
    async def handle_unexpected_error(message: types.Message, state: FSMContext, error: Exception, context: str = ""):
        """Handle unexpected system errors."""
        error_id = ErrorHandler._generate_error_id()
        logger.critical(f"Unexpected system error [{error_id}] in {context}: {error}\n{traceback.format_exc()}")
        
        await state.clear()
        
        user_message = (
            "⚠️ An unexpected system error occurred.\n"
            f"Reference ID: {error_id}\n"
            "Please use /start to restart your session."
        )
        await message.answer(user_message)
        
        return error_id
    
    @staticmethod
    def _generate_error_id() -> str:
        """Generate unique error identifier for tracking purposes."""
        import time
        import hashlib
        return hashlib.md5(f"{time.time()}".encode()).hexdigest()[:8]
    
    @staticmethod
    def log_security_event(event_type: str, user_id: int, details: Dict[str, Any]):
        """Log security-related events for monitoring and audit purposes."""
        logger.warning(f"Security event [{event_type}] User: {user_id} Details: {details}")