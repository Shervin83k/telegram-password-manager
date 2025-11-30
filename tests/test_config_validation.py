"""
Configuration validation and environment setup tests.
"""
import os
import pytest


def test_required_directories():
    """Verify existence of required project directories and modules.
    
    Checks:
    - Core application modules exist
    - Test directory structure is present
    - Essential files are available
    """
    required_paths = [
        'database.py',
        'encryption.py', 
        'bot.py',
        'tests/'
    ]
    
    for path in required_paths:
        assert os.path.exists(path), f"Required path missing: {path}"


def test_environment_variables():
    """Validate critical environment configuration.
    
    Verifies:
    - Bot token is configured
    - Encryption key is present and secure
    - Required environment variables are set
    """
    bot_token = os.getenv('BOT_TOKEN')
    encryption_key = os.getenv('ENCRYPTION_KEY')
    
    assert bot_token is not None, "BOT_TOKEN environment variable must be set"
    assert encryption_key is not None, "ENCRYPTION_KEY environment variable must be set"
    assert len(encryption_key) >= 32, "ENCRYPTION_KEY must be at least 32 characters for security"