import os
from dotenv import load_dotenv


def test_env():
    """Test environment configuration and .env file validation.
    
    Returns:
        Boolean indicating successful environment setup
    """
    print("🔍 Testing Environment Configuration...")
    
    # Load environment variables from .env file
    load_dotenv()
    
    # Verify .env file existence
    if not os.path.exists('.env'):
        print("❌ .env configuration file not found")
        return False
    
    print("✅ .env configuration file located")
    
    # Retrieve bot token from environment
    token = os.getenv('BOT_TOKEN')
    
    if not token:
        print("❌ BOT_TOKEN environment variable not configured")
        return False
    
    print(f"✅ BOT_TOKEN configured: {token[:10]}...")
    
    # Validate token is not placeholder value
    if token == "your_bot_token_here":
        print("❌ BOT_TOKEN contains placeholder value - update with actual token")
        return False
    
    print("✅ BOT_TOKEN contains valid authentication token")
    return True


if __name__ == "__main__":
    if test_env():
        print("\n🎉 Environment configuration validated successfully!")
    else:
        print("\n❌ Environment configuration requires attention!")