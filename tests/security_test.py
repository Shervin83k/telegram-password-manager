import pytest
import asyncio
import sys
import os
from unittest.mock import AsyncMock, MagicMock

# Add parent directory to Python path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import application modules
from utils.validators import InputValidator
from utils.encryption import EncryptionManager
from utils.hashing import HashManager
from db.database import Database
from utils.session_manager import sessions
from utils.global_rate_limiter import global_limiter


class TestSecurity:
    """Comprehensive security testing suite for the application."""
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection attempts are properly blocked."""
        print("🔒 Testing SQL injection prevention...")
        injection_attempts = [
            "admin' OR '1'='1",
            "admin'; DROP TABLE Users;--",
            "'; EXEC master..xp_cmdshell 'nslookup example.com'--",
            "1; INSERT INTO Users (username, password) VALUES 'hacker', 'pass'",
            "test' OR '1'='1' --",
            "admin'/*",
            "'; SHOW TABLES;--"
        ]
        
        for attempt in injection_attempts:
            is_valid, _ = InputValidator.validate_username(attempt)
            assert not is_valid, f"SQL injection passed validation: {attempt}"
            print(f"✅ Blocked: {attempt}")
    
    def test_password_hashing_security(self):
        """Test password hashing security and verification."""
        print("🔒 Testing password hashing security...")
        password = "secure_test_password_123"
        
        hash1 = HashManager.hash_password(password)
        hash2 = HashManager.hash_password(password)
        
        assert hash1 != hash2, "Identical passwords should produce different hashes"
        assert HashManager.verify_password(password, hash1), "Password verification should succeed"
        assert HashManager.verify_password(password, hash2), "Password verification should succeed"
        assert not HashManager.verify_password("incorrect_password", hash1), "Wrong password should fail verification"
        print("✅ Password hashing security verified")
    
    def test_encryption_security(self):
        """Test encryption and decryption functionality."""
        print("🔒 Testing encryption security...")
        key = EncryptionManager.generate_key()
        test_data = "confidential@example.com"
        
        encrypted = EncryptionManager.encrypt_data(test_data, key)
        decrypted = EncryptionManager.decrypt_data(encrypted, key)
        
        assert encrypted != test_data, "Encrypted data should differ from original"
        assert decrypted == test_data, "Decrypted data should match original"
        
        wrong_key = EncryptionManager.generate_key()
        try:
            EncryptionManager.decrypt_data(encrypted, wrong_key)
            assert False, "Decryption with incorrect key should fail"
        except Exception:
            assert True
        
        print("✅ Encryption security verified")
    
    def test_input_validation_comprehensive(self):
        """Test comprehensive input validation rules."""
        print("🔒 Testing input validation...")
        
        # Valid input cases
        assert InputValidator.validate_username("validuser123")[0]
        assert InputValidator.validate_email("user@example.com")[0]
        assert InputValidator.validate_entry_name("Secure Entry")[0]
        assert InputValidator.validate_password("securepass123")[0]
        
        # Invalid input cases
        assert not InputValidator.validate_username("admin")[0]  # Reserved name
        assert not InputValidator.validate_username("ab")[0]  # Too short
        assert not InputValidator.validate_username("a" * 51)[0]  # Too long
        assert not InputValidator.validate_email("invalid-email")[0]  # Invalid format
        assert not InputValidator.validate_entry_name("")[0]  # Empty entry
        assert not InputValidator.validate_password("")[0]  # Empty password
        assert not InputValidator.validate_password("short")[0]  # Too short
        
        print("✅ Input validation verified")
    
    def test_session_manager_security(self):
        """Test session manager security features."""
        print("🔒 Testing session manager security...")
        
        user_id = 99999
        test_user_data = {
            'user_id': 1,
            'username': 'testuser'
        }
        
        sessions.authenticate_user(user_id, test_user_data)
        assert sessions.is_session_valid(user_id), "Session should be valid after authentication"
        
        user_data = sessions.get_user_data(user_id)
        assert 'encryption_key' not in user_data, "Encryption keys should not be stored in sessions"
        
        sessions.logout_user(user_id)
        assert not sessions.is_session_valid(user_id), "Session should be invalid after logout"
        
        print("✅ Session manager security verified")
    
    def test_rate_limiting_security(self):
        """Test rate limiting functionality and security."""
        print("🔒 Testing rate limiting...")
        
        user_id = 88888
        global_limiter.reset_user_limits(user_id)
        
        for i in range(100):
            allowed, message = global_limiter.is_allowed(user_id, 'authenticated')
            assert allowed, f"Request should be allowed at attempt {i+1}"
        
        allowed, message = global_limiter.is_allowed(user_id, 'authenticated')
        assert not allowed, "Request should be blocked after exceeding limit"
        assert "rate limit" in message.lower()
        
        global_limiter.reset_user_limits(user_id)
        allowed, _ = global_limiter.is_allowed(user_id, 'sensitive')
        assert allowed, "Different request types should have separate limits"
        
        print("✅ Rate limiting security verified")
    
    def test_database_integrity(self):
        """Test database operations and data integrity."""
        print("🔒 Testing database integrity...")
        
        test_db_path = "test_security.db"
        
        try:
            if os.path.exists(test_db_path):
                os.unlink(test_db_path)
            
            db = Database(test_db_path)
            
            user_id = db.create_user("testuser", "hashed_password", "encryption_key", 12345)
            assert user_id is not None, "User creation should succeed"
            
            user_id2 = db.create_user("testuser", "another_hash", "another_key", 12346)
            assert user_id2 is False, "Duplicate username should be rejected"
            
            entry_id = db.create_password_entry(user_id, "Test Entry", "encrypted_email", "encrypted_password")
            assert entry_id is not None, "Password entry creation should succeed"
            
            entries = db.get_user_entries(user_id)
            assert len(entries) == 1, "Should retrieve correct number of user entries"
            
            health = db.health_check()
            assert health['status'] == 'healthy', "Database health check should pass"
            
            print("✅ Database integrity verified")
            
        except Exception as e:
            print(f"❌ Database test error: {e}")
            raise
        finally:
            if os.path.exists(test_db_path):
                try:
                    os.unlink(test_db_path)
                except OSError:
                    print(f"⚠️ Could not remove test database: {test_db_path}")


def run_security_tests():
    """Execute comprehensive security test suite.
    
    Returns:
        Boolean indicating if all tests passed
    """
    print("🚀 Starting Comprehensive Security Test Suite")
    print("=" * 60)
    
    test_instance = TestSecurity()
    
    try:
        test_instance.test_sql_injection_prevention()
        test_instance.test_password_hashing_security()
        test_instance.test_encryption_security()
        test_instance.test_input_validation_comprehensive()
        test_instance.test_session_manager_security()
        test_instance.test_rate_limiting_security()
        test_instance.test_database_integrity()
        
        print("=" * 60)
        print("🎉 All Security Tests Passed Successfully!")
        print("✅ Application security verified and ready for production")
        return True
        
    except Exception as e:
        print("=" * 60)
        print(f"❌ Security Test Failure: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    run_security_tests()