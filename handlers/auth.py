import logging
from aiogram import Router, F
from aiogram.filters import Command, CommandStart
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from db.database import db
from utils.encryption import generate_key
from utils.session_manager import sessions
from utils.logger import logger
from handlers.main_menu import get_main_menu_keyboard

auth_router = Router()


class AuthState(StatesGroup):
    """Authentication states for user registration and login."""
    waiting_for_username = State()
    waiting_for_password = State()
    waiting_for_key_confirmation = State()


def get_cancel_keyboard():
    """Return cancel keyboard for interruptible operations."""
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="❌ Cancel")]],
        resize_keyboard=True,
        one_time_keyboard=True
    )


def get_auth_choice_keyboard():
    """Return authentication choice keyboard for new/existing users."""
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📝 New user"), KeyboardButton(text="🔐 Already a user")],
            [KeyboardButton(text="❌ Cancel")]
        ],
        resize_keyboard=True,
        one_time_keyboard=True
    )


@auth_router.message(F.text == "❌ Cancel")
@auth_router.message(Command("cancel"))
async def cancel_operation(message: Message, state: FSMContext):
    """Cancel any ongoing operation and return to start menu."""
    await state.clear()
    await message.answer(
        "🔄 Operation cancelled. Returning to main menu.",
        reply_markup=ReplyKeyboardRemove()
    )
    await cmd_start(message, state)


@auth_router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    """Handle bot start command and provide authentication options."""
    try:
        await state.clear()
        
        user_id = message.from_user.id
        logging.info(f"User {user_id} initiated start command")
        
        if sessions.is_session_valid(user_id):
            await message.answer(
                "🎉 Welcome back!\n\n📱 Main Menu",
                reply_markup=get_main_menu_keyboard()
            )
            return
        
        await message.answer(
            "🤖 Welcome to Password Manager Bot\n\n"
            "🔒 Secure Password Management\n"
            "• End-to-end encryption\n"
            "• Your data remains private\n"
            "• Automatic session timeout\n\n"
            "Please select an option below to continue:",
            reply_markup=get_auth_choice_keyboard()
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "cmd_start")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease try again."
        )


@auth_router.message(F.text == "📝 New user")
async def new_user_choice(message: Message, state: FSMContext):
    """Handle new user registration flow initiation."""
    await state.update_data(is_signup=True)
    await message.answer(
        "👤 Please choose a username for your account:\n\n"
        "Requirements:\n"
        "• 3-50 characters in length\n"
        "• Letters, numbers, and underscores only\n\n"
        "Use 'Cancel' or /cancel to return to main menu",
        reply_markup=get_cancel_keyboard()
    )
    await state.set_state(AuthState.waiting_for_username)


@auth_router.message(F.text == "🔐 Already a user")
async def existing_user_choice(message: Message, state: FSMContext):
    """Handle existing user login flow initiation."""
    await state.update_data(is_signup=False)
    await message.answer(
        "👤 Please enter your username:\n\n"
        "Use 'Cancel' or /cancel to return to main menu",
        reply_markup=get_cancel_keyboard()
    )
    await state.set_state(AuthState.waiting_for_username)


@auth_router.message(AuthState.waiting_for_username)
async def process_username(message: Message, state: FSMContext):
    """Process and validate username input."""
    try:
        username = message.text.strip()
        
        if username.lower() in ['cancel', 'back']:
            await cancel_operation(message, state)
            return
        
        if not username:
            await message.answer("❌ Please enter a valid username:")
            return
        
        if len(username) < 3 or len(username) > 50:
            await message.answer("❌ Username must be between 3 and 50 characters:")
            return
        
        if not all(c.isalnum() or c == '_' for c in username):
            await message.answer("❌ Username can only contain letters, numbers, and underscores:")
            return
        
        current_data = await state.get_data()
        is_signup = current_data.get('is_signup')
        
        if is_signup is None:
            is_signup = not db.username_exists(username)
        
        await state.update_data(username=username, is_signup=is_signup)
        
        if is_signup and db.username_exists(username):
            await message.answer(
                f"❌ Username '{username}' is already registered.\n\n"
                "Please choose a different username:",
                reply_markup=get_cancel_keyboard()
            )
            return
        
        await message.answer(
            "🔑 Please enter your password:\n\n"
            "Requirements:\n"
            "• Minimum 6 characters\n"
            "• Maximum 128 characters\n\n"
            "Use 'Cancel' or /cancel to return to main menu",
            reply_markup=get_cancel_keyboard()
        )
        await state.set_state(AuthState.waiting_for_password)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_username")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@auth_router.message(AuthState.waiting_for_password)
async def process_password(message: Message, state: FSMContext):
    """Process and validate password input."""
    try:
        password = message.text.strip()
        
        if password.lower() in ['cancel', 'back']:
            await cancel_operation(message, state)
            return
        
        if not password:
            await message.answer("❌ Please enter a valid password:")
            return
        
        if len(password) < 6:
            await message.answer("❌ Password must be at least 6 characters:")
            return
        
        if len(password) > 128:
            await message.answer("❌ Password must be less than 128 characters:")
            return
        
        data = await state.get_data()
        username = data.get('username')
        is_signup = data.get('is_signup', False)
        
        if is_signup:
            encryption_key = generate_key()
            success = db.create_user(
                username, 
                db.hash_password(password), 
                encryption_key, 
                message.from_user.id
            )
            
            if success:
                await message.answer(
                    f"✅ Account created successfully!\n\n"
                    f"🔑 YOUR ENCRYPTION KEY:\n"
                    f"<code>{encryption_key}</code>\n\n"
                    "⚠️ IMPORTANT: Save this key securely\n"
                    "• Required for password decryption\n"
                    "• Cannot be recovered if lost\n"
                    "• Store in a secure location\n\n"
                    "Please confirm once you have saved your key to proceed.",
                    reply_markup=ReplyKeyboardMarkup(
                        keyboard=[[KeyboardButton(text="✅ I have saved my key")]],
                        resize_keyboard=True
                    )
                )
                await state.set_state(AuthState.waiting_for_key_confirmation)
                logging.info(f"User {message.from_user.id} registered with username: {username}")
            else:
                await message.answer(
                    "❌ Account creation failed. Please try again.",
                    reply_markup=get_auth_choice_keyboard()
                )
                await state.clear()
        else:
            user_data = db.get_user_by_username(username)
            if user_data and user_data['password_hash'] == db.hash_password(password):
                sessions.authenticate_user(
                    user_id=message.from_user.id,
                    user_data={
                        'user_id': user_data['id'],
                        'username': username
                    }
                )
                
                await message.answer(
                    "✅ Login successful!\n\n📱 Main Menu",
                    reply_markup=get_main_menu_keyboard()
                )
                logging.info(f"User {message.from_user.id} logged in as: {username}")
                await state.clear()
            else:
                await message.answer(
                    "❌ Invalid username or password.\n\n"
                    "Please try again or return to main menu.",
                    reply_markup=get_cancel_keyboard()
                )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_password")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@auth_router.message(AuthState.waiting_for_key_confirmation)
async def process_key_confirmation(message: Message, state: FSMContext):
    """Process encryption key confirmation and complete user setup."""
    try:
        if message.text == "✅ I have saved my key":
            data = await state.get_data()
            username = data.get('username')
            
            user_data = db.get_user_by_username(username)
            if user_data:
                sessions.authenticate_user(
                    user_id=message.from_user.id,
                    user_data={
                        'user_id': user_data['id'],
                        'username': username
                    }
                )
                
                await message.answer(
                    "🎉 Setup complete!\n\n"
                    "📱 Main Menu\n"
                    "• View and manage password entries\n"
                    "• Add new secure entries\n"
                    "• All data encrypted with your key\n\n"
                    "🔒 Security Features\n"
                    "• Automatic logout after inactivity\n"
                    "• End-to-end encryption\n"
                    "• Keys remain on your device",
                    reply_markup=get_main_menu_keyboard()
                )
                await state.clear()
            else:
                await message.answer(
                    "❌ User account not found. Please start over with /start",
                    reply_markup=ReplyKeyboardRemove()
                )
        else:
            await message.answer(
                "⚠️ Please confirm that you have saved your encryption key by clicking the button below.",
                reply_markup=ReplyKeyboardMarkup(
                    keyboard=[[KeyboardButton(text="✅ I have saved my key")]],
                    resize_keyboard=True
                )
            )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_key_confirmation")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )