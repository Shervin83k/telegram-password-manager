import time
import logging
from cryptography.fernet import Fernet
import base64

logger = logging.getLogger(__name__)


class SecureSessionManager:
    """Secure session management with encrypted session storage."""
    
    def __init__(self):
        self.sessions = {}
        self.memory_key = Fernet.generate_key()
        self.fernet = Fernet(self.memory_key)
    
    def encrypt_session_data(self, data: dict) -> str:
        """Encrypt session data before storing in memory.
        
        Args:
            data: Session data dictionary to encrypt
            
        Returns:
            Base64 encoded encrypted session data
        """
        try:
            data_str = str(data)
            encrypted = self.fernet.encrypt(data_str.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Session data encryption failed: {e}")
            raise
    
    def decrypt_session_data(self, encrypted_data: str) -> dict:
        """Decrypt session data retrieved from memory.
        
        Args:
            encrypted_data: Base64 encoded encrypted session data
            
        Returns:
            Decrypted session data dictionary
        """
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(encrypted).decode()
            return eval(decrypted)
        except Exception as e:
            logger.warning(f"Session data decryption failed: {e}")
            return {}
    
    def update_user_activity(self, user_id: int):
        """Update user activity timestamp.
        
        Args:
            user_id: User identifier to update activity for
        """
        if user_id not in self.sessions:
            self.sessions[user_id] = self.encrypt_session_data({
                'last_activity': time.time(),
                'is_authenticated': False
            })
        else:
            session_data = self.decrypt_session_data(self.sessions[user_id])
            session_data['last_activity'] = time.time()
            self.sessions[user_id] = self.encrypt_session_data(session_data)