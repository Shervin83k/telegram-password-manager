import time
import logging
import json
from typing import Dict, Any
from aiogram import Bot
from aiogram.types import Message
from cryptography.fernet import Fernet
import base64

logger = logging.getLogger(__name__)


class SecureSessionManager:
    """Enhanced session manager with memory encryption and security features."""
    
    def __init__(self, session_timeout: int = 180):  # 3 minutes
        self.sessions: Dict[int, str] = {}  # Encrypted session data storage
        self.session_timeout = session_timeout
        self.max_login_attempts = 3
        self.login_attempts: Dict[int, int] = {}
        
        # Generate encryption key for memory protection
        self.memory_key = Fernet.generate_key()
        self.fernet = Fernet(self.memory_key)
    
    def _encrypt_session_data(self, data: Dict[str, Any]) -> str:
        """Encrypt session data before storing in memory.
        
        Args:
            data: Session data dictionary to encrypt
            
        Returns:
            Base64 encoded encrypted session data
        """
        try:
            data_str = json.dumps(data)
            encrypted = self.fernet.encrypt(data_str.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Session data encryption failed: {e}")
            return ""
    
    def _decrypt_session_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt session data retrieved from memory.
        
        Args:
            encrypted_data: Base64 encoded encrypted session data
            
        Returns:
            Decrypted session data dictionary
        """
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(encrypted).decode()
            return json.loads(decrypted)
        except Exception as e:
            logger.error(f"Session data decryption failed: {e}")
            return {}
    
    def update_user_activity(self, user_id: int) -> bool:
        """Update user activity timestamp with encrypted session storage.
        
        Args:
            user_id: User identifier to update activity for
            
        Returns:
            True if activity was updated successfully
        """
        if not self._is_user_id_valid(user_id):
            return False
            
        current_time = time.time()
        
        if user_id not in self.sessions:
            session_data = {
                'last_activity': current_time,
                'login_attempts': 0,
                'is_authenticated': False
            }
            self.sessions[user_id] = self._encrypt_session_data(session_data)
        else:
            session_data = self._decrypt_session_data(self.sessions[user_id])
            session_data['last_activity'] = current_time
            self.sessions[user_id] = self._encrypt_session_data(session_data)
        
        return True
    
    def is_session_valid(self, user_id: int) -> bool:
        """Check if user session is valid and authenticated.
        
        Args:
            user_id: User identifier to validate session for
            
        Returns:
            True if session is valid and authenticated
        """
        if not self._is_user_id_valid(user_id):
            return False
            
        if user_id not in self.sessions:
            return False
        
        try:
            session_data = self._decrypt_session_data(self.sessions[user_id])
            current_time = time.time()
            last_activity = session_data.get('last_activity', 0)
            
            if current_time - last_activity > self.session_timeout:
                del self.sessions[user_id]
                return False
            
            return session_data.get('is_authenticated', False)
            
        except Exception as e:
            logger.error(f"Session validation failed for user {user_id}: {e}")
            return False
    
    def authenticate_user(self, user_id: int, user_data: Dict[str, Any]) -> bool:
        """Authenticate user and create encrypted session.
        
        Args:
            user_id: User identifier to authenticate
            user_data: User information to store in session
            
        Returns:
            True if authentication was successful
        """
        if not self._is_user_id_valid(user_id):
            return False
        
        session_data = {
            'last_activity': time.time(),
            'is_authenticated': True,
            'user_id': user_data.get('user_id'),
            'username': user_data.get('username'),
            'login_attempts': 0
        }
        
        self.sessions[user_id] = self._encrypt_session_data(session_data)
        
        if user_id in self.login_attempts:
            self.login_attempts[user_id] = 0
            
        logger.info(f"User {user_id} authenticated successfully")
        return True
    
    def get_user_data(self, user_id: int) -> Dict[str, Any]:
        """Retrieve user data from encrypted session.
        
        Args:
            user_id: User identifier to retrieve data for
            
        Returns:
            User session data dictionary
        """
        if user_id in self.sessions:
            return self._decrypt_session_data(self.sessions[user_id])
        return {}
    
    def logout_user(self, user_id: int) -> bool:
        """Log out user and clear session authentication.
        
        Args:
            user_id: User identifier to log out
            
        Returns:
            True if logout was successful
        """
        if user_id in self.sessions:
            session_data = {
                'last_activity': time.time(),
                'is_authenticated': False
            }
            self.sessions[user_id] = self._encrypt_session_data(session_data)
            
            logger.info(f"User {user_id} logged out")
            return True
        return False
    
    def record_login_attempt(self, user_id: int) -> bool:
        """Record failed login attempt and check for blocking.
        
        Args:
            user_id: User identifier to record attempt for
            
        Returns:
            True if user can continue attempting, False if blocked
        """
        if user_id not in self.login_attempts:
            self.login_attempts[user_id] = 0
        
        self.login_attempts[user_id] += 1
        
        if self.login_attempts[user_id] >= self.max_login_attempts:
            logger.warning(f"User {user_id} exceeded maximum login attempts")
            return False
        
        return True
    
    def get_remaining_attempts(self, user_id: int) -> int:
        """Get remaining login attempts for user.
        
        Args:
            user_id: User identifier to check attempts for
            
        Returns:
            Number of remaining login attempts
        """
        if user_id in self.login_attempts:
            return max(0, self.max_login_attempts - self.login_attempts[user_id])
        return self.max_login_attempts
    
    async def wipe_user_chat(self, user_id: int, bot: Bot, message: Message = None):
        """Clear user chat and notify about session expiration.
        
        Args:
            user_id: User identifier to wipe chat for
            bot: Bot instance for sending messages
            message: Optional message to delete
        """
        try:
            if message:
                try:
                    await message.delete()
                except Exception as e:
                    logger.warning(f"Message deletion failed for user {user_id}: {e}")
            
            warning_message = await bot.send_message(
                user_id,
                "🔒 Session Expired\n\n"
                "Your session has ended due to inactivity.\n"
                "Please use /start to begin a new session."
            )
            
            logger.info(f"Session expired for user {user_id}")
            
        except Exception as e:
            logger.error(f"Chat wipe failed for user {user_id}: {e}")
    
    def _is_user_id_valid(self, user_id: int) -> bool:
        """Validate user identifier format.
        
        Args:
            user_id: User identifier to validate
            
        Returns:
            True if user ID is valid
        """
        return isinstance(user_id, int) and user_id > 0
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions from memory."""
        current_time = time.time()
        expired_users = []
        
        for user_id, encrypted_data in self.sessions.items():
            try:
                session_data = self._decrypt_session_data(encrypted_data)
                last_activity = session_data.get('last_activity', 0)
                if current_time - last_activity > self.session_timeout:
                    expired_users.append(user_id)
            except Exception as e:
                logger.error(f"Session expiry check failed for user {user_id}: {e}")
                expired_users.append(user_id)
        
        for user_id in expired_users:
            if user_id in self.sessions:
                del self.sessions[user_id]
            logger.info(f"Expired session cleaned up for user {user_id}")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session management statistics.
        
        Returns:
            Dictionary containing session statistics
        """
        active_sessions = 0
        authenticated_sessions = 0
        
        for user_id, encrypted_data in self.sessions.items():
            try:
                session_data = self._decrypt_session_data(encrypted_data)
                if self._is_session_active(session_data):
                    active_sessions += 1
                    if session_data.get('is_authenticated', False):
                        authenticated_sessions += 1
            except Exception as e:
                logger.error(f"Session stats retrieval failed for user {user_id}: {e}")
        
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': active_sessions,
            'authenticated_sessions': authenticated_sessions,
            'login_attempts': len(self.login_attempts)
        }
    
    def _is_session_active(self, session_data: Dict[str, Any]) -> bool:
        """Check if session is within timeout period.
        
        Args:
            session_data: Session data to check
            
        Returns:
            True if session is still active
        """
        current_time = time.time()
        last_activity = session_data.get('last_activity', 0)
        return current_time - last_activity <= self.session_timeout


# Global session manager instance
sessions = SecureSessionManager()