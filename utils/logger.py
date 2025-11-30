import logging
import sys
import uuid
from datetime import datetime
from typing import Optional


class Logger:
    """Centralized logging management for the application."""
    
    def __init__(self):
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging with console and file handlers."""
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        formatter = logging.Formatter(
            '[%(asctime)s][%(name)s][%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console output handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File output handler
        file_handler = logging.FileHandler('bot.log', encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance for specific module.
        
        Args:
            name: Module name for the logger
            
        Returns:
            Configured logger instance
        """
        return logging.getLogger(name)
    
    def log_user_action(self, action: str, user_id: int, details: str = ""):
        """Log user authentication and interaction events.
        
        Args:
            action: Type of user action performed
            user_id: User identifier
            details: Additional context information
        """
        logger = self.get_logger("user_actions")
        if details:
            logger.info(f"User {user_id} - {action} - {details}")
        else:
            logger.info(f"User {user_id} - {action}")
    
    def log_unexpected_error(self, error: Exception, context: str) -> str:
        """Log unexpected application errors with tracking ID.
        
        Args:
            error: Exception that occurred
            context: Operation context where error happened
            
        Returns:
            Unique error identifier for tracking
        """
        logger = self.get_logger("errors")
        error_id = str(uuid.uuid4())[:8]
        logger.error(f"ErrorID: {error_id} - Context: {context} - Error: {str(error)}", exc_info=True)
        return error_id
    
    def log_security_event(self, event: str, user_id: Optional[int] = None):
        """Log security-related events for monitoring.
        
        Args:
            event: Security event description
            user_id: Optional user identifier
        """
        logger = self.get_logger("security")
        if user_id:
            logger.warning(f"Security event - User {user_id} - {event}")
        else:
            logger.warning(f"Security event - {event}")
    
    def log_admin_action(self, action: str, details: str = ""):
        """Log administrative actions for audit purposes.
        
        Args:
            action: Admin operation performed
            details: Additional operation context
        """
        logger = self.get_logger("admin")
        if details:
            logger.info(f"Admin action - {action} - {details}")
        else:
            logger.info(f"Admin action - {action}")


# Global logger instance
logger = Logger()


def setup_logger():
    """Initialize and return global logger instance.
    
    Returns:
        Configured Logger instance
    """
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get module-specific logger instance.
    
    Args:
        name: Module name for logger
        
    Returns:
        Configured logger instance
    """
    return logger.get_logger(name)


def log_user_action(action: str, user_id: int, details: str = ""):
    """Log user action through global logger.
    
    Args:
        action: Type of user action
        user_id: User identifier
        details: Additional context information
    """
    logger.log_user_action(action, user_id, details)


def log_unexpected_error(error: Exception, context: str) -> str:
    """Log unexpected error through global logger.
    
    Args:
        error: Exception that occurred
        context: Operation context
        
    Returns:
        Unique error identifier
    """
    return logger.log_unexpected_error(error, context)