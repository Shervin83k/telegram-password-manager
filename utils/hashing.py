import bcrypt
import logging

logger = logging.getLogger("hashing")


class HashManager:
    """Secure password hashing and verification using bcrypt."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt with salt.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password as string
            
        Raises:
            Exception: If hashing operation fails
        """
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against stored hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Previously hashed password for comparison
            
        Returns:
            True if password matches hash, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'), 
                hashed_password.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False