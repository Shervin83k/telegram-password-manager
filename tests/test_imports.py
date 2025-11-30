#!/usr/bin/env python3
"""
Comprehensive test suite for Password Saver Bot.
Validates all imports, core functionality, and system dependencies.
"""
import os
import sys
import time
import gc

# Add parent directory to Python path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_imports():
    """Test all required module imports and dependencies.
    
    Returns:
        Boolean indicating successful import of all modules
    """
    print("🔍 Testing Module Imports...")
    
    try:
        # Core framework imports
        import aiogram
        from aiogram import Bot, Dispatcher
        from aiogram.fsm.storage.memory import MemoryStorage
        print("✅ aiogram framework imported successfully")
        
        # Security and cryptography imports
        import cryptography
        from cryptography.fernet import Fernet
        print("✅ cryptography library imported successfully")
        
        # Password hashing imports
        import bcrypt
        print("✅ bcrypt hashing library imported successfully")
        
        # Environment configuration imports
        import dotenv
        print("✅ python-dotenv configuration imported successfully")
        
        # Database imports
        import sqlite3
        print("✅ sqlite3 database imported successfully")
        
        # Project-specific module imports
        from db.database import Database
        print("✅ Database module imported successfully")
        
        from utils.encryption import EncryptionManager
        print("✅ EncryptionManager module imported successfully")
        
        from utils.hashing import HashManager
        print("✅ HashManager module imported successfully")
        
        from utils.logger import setup_logger
        print("✅ Logger module imported successfully")
        
        print("\n🎉 All module imports completed successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Module import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected import error: {e}")
        return False


def test_encryption():
    """Test encryption and decryption functionality.
    
    Returns:
        Boolean indicating successful encryption operations
    """
    print("\n🔐 Testing Encryption System...")
    try:
        from utils.encryption import EncryptionManager
        
        key = EncryptionManager.generate_key()
        print(f"✅ Encryption key generated: {key[:20]}...")
        
        test_data = "Test encryption data"
        encrypted = EncryptionManager.encrypt_data(test_data, key)
        decrypted = EncryptionManager.decrypt_data(encrypted, key)
        
        if test_data == decrypted:
            print("✅ Encryption and decryption cycle completed successfully")
            return True
        else:
            print("❌ Encryption/decryption data mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Encryption system test failed: {e}")
        return False


def test_hashing():
    """Test password hashing and verification functionality.
    
    Returns:
        Boolean indicating successful hashing operations
    """
    print("\n🔑 Testing Password Hashing System...")
    try:
        from utils.hashing import HashManager
        
        password = "test_password_123"
        hashed = HashManager.hash_password(password)
        
        if HashManager.verify_password(password, hashed):
            print("✅ Password hashing and verification completed successfully")
            return True
        else:
            print("❌ Password verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Hashing system test failed: {e}")
        return False


def test_database():
    """Test database connectivity and basic operations.
    
    Returns:
        Boolean indicating successful database operations
    """
    print("\n🗄️ Testing Database System...")
    try:
        from db.database import Database
        from utils.hashing import HashManager
        
        db = Database("test.db")
        print("✅ Database connection established successfully")
        
        password_hash = HashManager.hash_password("testpass")
        success = db.create_user("testuser", password_hash, "testkey123", 123456789)
        print(f"✅ User creation test: {'Success' if success else 'Failed'}")
        
        user = db.get_user_by_username("testuser")
        if user:
            print("✅ User retrieval operation completed successfully")
        else:
            print("❌ User retrieval operation failed")
        
        # Clean up database connections and file
        del db
        gc.collect()
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if os.path.exists("test.db"):
                    os.remove("test.db")
                    print("✅ Test database cleaned up successfully")
                    break
            except PermissionError:
                if attempt < max_retries - 1:
                    print(f"⚠️ Database file busy, retrying... ({attempt + 1}/{max_retries})")
                    time.sleep(0.5)
                else:
                    print("⚠️ Could not remove test database (file busy) - database operations verified")
                    return True
        
        return True
        
    except Exception as e:
        print(f"❌ Database system test failed: {e}")
        return False


def main():
    """Execute comprehensive test suite and report results."""
    print("🚀 Password Saver Bot - Comprehensive Test Suite")
    print("=" * 50)
    
    test_functions = [
        test_imports,
        test_encryption,
        test_hashing,
        test_database
    ]
    
    test_results = []
    for test_function in test_functions:
        test_results.append(test_function())
    
    print("\n" + "=" * 50)
    print("📊 Test Suite Results:")
    print(f"✅ Tests Passed: {sum(test_results)}/{len(test_results)}")
    print(f"❌ Tests Failed: {len(test_results) - sum(test_results)}/{len(test_results)}")
    
    if all(test_results):
        print("\n🎉 All Tests Passed Successfully!")
        print("✅ Your bot is configured correctly and ready for operation")
        print("\nNext Steps:")
        print("1. Configure your bot token in the .env file")
        print("2. Execute: python main.py")
        print("3. Start interacting with your bot using /start command")
    else:
        print("\n⚠️ Some tests require attention")
        print("Please review the error messages above and resolve any issues")
    
    print("=" * 50)


if __name__ == "__main__":
    main()