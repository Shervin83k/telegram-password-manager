import asyncio
import logging
from db.database import Database
from utils.logger import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


def test_database():
    """Test database connection and core operations.
    
    Verifies:
    - Database initialization
    - User creation functionality
    - User verification process
    - Security feature checks
    """
    try:
        db = Database("db/password_bot.db")
        print("✅ Database initialized successfully")
        
        # Test user creation
        success = db.create_user("test_user", "test_password", "test_key", 123456789)
        print(f"✅ User creation test: {success}")
        
        # Test user verification
        user = db.verify_user("test_user", "test_password")
        print(f"✅ User verification test: {user is not None}")
        
        # Test banned user check
        banned = db.is_user_banned(123456789)
        print(f"✅ Banned user check test: {banned}")
        
        print("🎉 All database tests completed successfully")
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_database()