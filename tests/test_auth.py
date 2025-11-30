import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from aiogram.fsm.context import FSMContext
from handlers.auth import process_username, process_password, cancel_operation


class TestAuthentication:
    """Test suite for authentication handler functionality."""
    
    @pytest.mark.asyncio
    async def test_valid_username_signup(self):
        """Test successful username validation during signup."""
        message = AsyncMock()
        message.text = "validuser123"
        message.from_user.id = 12345
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data = AsyncMock(return_value={'is_signup': True})
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        with patch('handlers.auth.db.username_exists') as mock_exists:
            mock_exists.return_value = False
            
            await process_username(message, state)
            
            state.set_state.assert_called_once()
            message.answer.assert_called_with("🔑 Please enter your password:")
    
    @pytest.mark.asyncio
    async def test_existing_username_signup(self):
        """Test rejection of existing username during signup."""
        message = AsyncMock()
        message.text = "existinguser"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data = AsyncMock(return_value={'is_signup': True})
        
        with patch('handlers.auth.db.username_exists') as mock_exists:
            mock_exists.return_value = True
            
            await process_username(message, state)
            
            message.answer.assert_called_with(
                "❌ Username 'existinguser' is already registered.\n\n"
                "Please choose a different username:"
            )
    
    @pytest.mark.asyncio
    async def test_invalid_username_short(self):
        """Test rejection of username that is too short."""
        message = AsyncMock()
        message.text = "ab"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_username(message, state)
        
        message.answer.assert_called_with(
            "❌ Username must be between 3 and 50 characters:"
        )
    
    @pytest.mark.asyncio
    async def test_invalid_username_special_chars(self):
        """Test rejection of username with invalid characters."""
        message = AsyncMock()
        message.text = "user@name"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_username(message, state)
        
        message.answer.assert_called_with(
            "❌ Username can only contain letters, numbers, and underscores:"
        )
    
    @pytest.mark.asyncio
    async def test_valid_password_signup(self):
        """Test successful password validation during signup."""
        message = AsyncMock()
        message.text = "securepassword123"
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
                
                mock_create.assert_called_once()
                state.set_state.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_invalid_password_short(self):
        """Test rejection of password that is too short."""
        message = AsyncMock()
        message.text = "123"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data = AsyncMock(return_value={'is_signup': True})
        
        await process_password(message, state)
        
        message.answer.assert_called_with(
            "❌ Password must be at least 6 characters:"
        )
    
    @pytest.mark.asyncio
    async def test_cancel_operation_username(self):
        """Test cancellation during username entry."""
        message = AsyncMock()
        message.text = "cancel"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        with patch('handlers.auth.cancel_operation') as mock_cancel:
            await process_username(message, state)
            mock_cancel.assert_called_once_with(message, state)
    
    @pytest.mark.asyncio
    async def test_cancel_operation_password(self):
        """Test cancellation during password entry."""
        message = AsyncMock()
        message.text = "cancel"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data = AsyncMock(return_value={'is_signup': True})
        
        with patch('handlers.auth.cancel_operation') as mock_cancel:
            await process_password(message, state)
            mock_cancel.assert_called_once_with(message, state)