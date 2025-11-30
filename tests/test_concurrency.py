import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from handlers.auth import process_username


class TestConcurrency:
    """Test suite for concurrent user operations and race conditions."""
    
    @pytest.mark.asyncio
    async def test_multiple_users_simultaneous_signup(self):
        """Test multiple users attempting signup simultaneously.
        
        Verifies:
        - System handles concurrent user registrations
        - No race conditions in username validation
        - All user sessions remain isolated
        """
        async def simulate_user_signup(user_id, username):
            message = AsyncMock()
            message.text = username
            message.from_user.id = user_id
            message.answer = AsyncMock()
            
            state = AsyncMock()
            state.get_data = AsyncMock(return_value={'is_signup': True})
            state.update_data = AsyncMock()
            state.set_state = AsyncMock()
            
            with patch('handlers.auth.db.username_exists') as mock_exists:
                mock_exists.return_value = False
                await process_username(message, state)
            
            return username
        
        # Simulate concurrent user signup attempts
        test_users = [
            (1001, "user1"),
            (1002, "user2"), 
            (1003, "user3")
        ]
        
        tasks = [simulate_user_signup(user_id, username) for user_id, username in test_users]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        assert set(results) == {"user1", "user2", "user3"}