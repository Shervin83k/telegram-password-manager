import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger('utils.encryption')


def generate_key() -> str:
    """
    Generate a new Fernet encryption key.
    
    Returns:
        Base64 encoded encryption key as string
    """
    try:
        key = Fernet.generate_key()
        return key.decode('utf-8')
    except Exception as e:
        logger.error(f"Error generating encryption key: {str(e)}")
        raise


def encrypt_data(data: str, encryption_key: str) -> str:
    """
    Encrypt data using Fernet symmetric encryption.
    
    Args:
        data: Plain text data to encrypt
        encryption_key: Base64 encoded encryption key
    
    Returns:
        Base64 encoded encrypted data
    """
    try:
        if not data:
            return ""
        
        key_bytes = encryption_key.encode('utf-8') if isinstance(encryption_key, str) else encryption_key
        fernet = Fernet(key_bytes)
        encrypted_data = fernet.encrypt(data.encode('utf-8'))
        
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Error encrypting data: {str(e)}")
        raise


def decrypt_data(encrypted_data: str, encryption_key: str) -> str:
    """
    Decrypt data using Fernet symmetric encryption.
    
    Args:
        encrypted_data: Base64 encoded encrypted data
        encryption_key: Base64 encoded encryption key
    
    Returns:
        Decrypted plain text data
    """
    try:
        if not encrypted_data:
            return ""
        
        key_bytes = encryption_key.encode('utf-8') if isinstance(encryption_key, str) else encryption_key
        fernet = Fernet(key_bytes)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        decrypted_data = fernet.decrypt(encrypted_bytes)
        
        return decrypted_data.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Error decrypting data: {str(e)}")
        raise


def validate_encryption_key(key: str) -> bool:
    """
    Validate if a string is a valid Fernet key.
    
    Args:
        key: Potential encryption key to validate
    
    Returns:
        True if valid encryption key, False otherwise
    """
    try:
        if not key:
            return False
        
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        Fernet(key_bytes)
        return True
        
    except Exception:
        return False


def test_encryption() -> bool:
    """
    Test encryption/decryption functionality.
    
    Returns:
        True if test passes, False otherwise
    """
    try:
        test_data = "Test encryption data"
        test_key = generate_key()
        
        encrypted = encrypt_data(test_data, test_key)
        decrypted = decrypt_data(encrypted, test_key)
        
        if test_data == decrypted:
            logger.info("Encryption module test completed successfully")
            return True
        else:
            logger.error("Encryption module test failed - data mismatch")
            return False
            
    except Exception as e:
        logger.error(f"Encryption module test error: {str(e)}")
        return False


if __name__ == "__main__":
    test_encryption()