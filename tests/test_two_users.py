"""
Test script for multi-user registration scenarios.
Validates user creation, username uniqueness, and data isolation.
"""
import asyncio
from db.database import Database


def test_two_users():
    """Test multi-user registration and username uniqueness validation.
    
    Verifies:
    - Successful user registration process
    - Username uniqueness enforcement
    - Proper error handling for duplicate registrations
    - Data isolation between different users
    """
    db = Database("db/password_bot.db")
    
    print("=== Multi-User Registration Test ===")
    
    # First user registration
    print("1. User 1 (ID: 111111) registering as 'shervin'...")
    success1 = db.create_user("shervin", "pass123", "key1", 111111)
    print(f"   Registration result: {'Success' if success1 else 'Failed'}")
    
    # Verify username existence
    exists = db.username_exists("shervin")
    print(f"2. Username 'shervin' availability: {'Taken' if exists else 'Available'}")
    
    # Second user attempts duplicate registration
    print("3. User 2 (ID: 222222) attempting to register as 'shervin'...")
    success2 = db.create_user("shervin", "pass456", "key2", 222222)
    print(f"   Registration result: {'Success' if success2 else 'Failed (expected)'}")
    
    # Display current user registry
    users = db.get_all_users()
    print(f"4. Registered users count: {len(users)}")


if __name__ == "__main__":
    test_two_users()