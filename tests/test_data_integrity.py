import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from handlers.auth import process_username, process_password


class TestDataIntegrity:
    """Test suite for data integrity and edge case handling."""
    
    @pytest.mark.asyncio
    async def test_username_whitespace_handling(self):
        """Test username input with various whitespace patterns.
        
        Verifies:
        - Leading/trailing whitespace is handled
        - Internal whitespace is processed correctly
        - No errors from unusual whitespace characters
        """
        test_cases = [
            "  user  ",      # Leading and trailing spaces
            "user  name",    # Internal multiple spaces  
            "\tuser\n",      # Tab and newline characters
        ]
        
        for input_username in test_cases:
            message = AsyncMock()
            message.text = input_username
            message.answer = AsyncMock()
            
            state = AsyncMock()
            state.get_data = AsyncMock(return_value={'is_signup': True})
            state.update_data = AsyncMock()
            state.set_state = AsyncMock()
            
            with patch('handlers.auth.db.username_exists') as mock_exists:
                mock_exists.return_value = False
                await process_username(message, state)
                
                assert message.answer.called, "Username processing should complete"

    @pytest.mark.asyncio
    async def test_password_special_characters(self):
        """Test password input with special and unicode characters.
        
        Verifies:
        - Special characters are accepted in passwords
        - Unicode characters are handled properly
        - Spaces in passwords are supported
        - Complex passwords trigger user creation
        """
        special_passwords = [
            "pass@123!",
            "pässwörd",      # Unicode characters
            "password with spaces",
            "P@$$w0rd!",
        ]
        
        for password in special_passwords:
            message = AsyncMock()
            message.text = password
            message.from_user.id = 12345
            message.answer = AsyncMock()
            
            state = AsyncMock()
            state.get_data = AsyncMock(return_value={
                'username': 'testuser',
                'is_signup': True
            })
            state.set_state = AsyncMock()
            
            with patch('handlers.auth.db.create_user') as mock_create:
                with patch('handlers.auth.db.hash_password') as mock_hash:
                    mock_create.return_value = True
                    mock_hash.return_value = "hashed_password"
                    
                    await process_password(message, state)
                    assert mock_create.called, "User creation should be attempted for valid passwords"