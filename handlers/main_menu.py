import logging
from aiogram import F, Router, types
from aiogram.fsm.context import FSMContext
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardRemove

from db.database import db
from utils.session_manager import sessions
from utils.logger import logger

router = Router()


def get_main_menu_keyboard():
    """Return main menu navigation keyboard."""
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📋 List my entries")],
            [KeyboardButton(text="➕ Add new entry")],
            [KeyboardButton(text="🔒 Logout")]
        ],
        resize_keyboard=True,
        one_time_keyboard=True
    )


def get_back_to_menu_keyboard():
    """Return back to menu navigation keyboard."""
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="⬅️ Back to Menu")]],
        resize_keyboard=True,
        one_time_keyboard=True
    )


@router.message(F.text == "📋 List my entries")
async def list_entries(message: types.Message, state: FSMContext):
    """Display all password entries for the authenticated user."""
    try:
        user_id = message.from_user.id
        
        if not sessions.is_session_valid(user_id):
            await message.answer(
                "❌ Session expired. Please log in again.", 
                reply_markup=ReplyKeyboardRemove()
            )
            return
        
        user_data = sessions.get_user_data(user_id)
        username = user_data.get('username')
        
        if not username:
            await message.answer(
                "❌ Session expired. Please log in again.", 
                reply_markup=ReplyKeyboardRemove()
            )
            return
        
        db_user = db.get_user_by_username(username)
        if not db_user:
            await message.answer(
                "❌ User not found. Please log in again.", 
                reply_markup=ReplyKeyboardRemove()
            )
            return
        
        entries = db.get_password_entries(db_user['id'])
        
        if not entries:
            await message.answer(
                "📝 No password entries found.\n\n"
                "Use '➕ Add new entry' to create your first secure entry.",
                reply_markup=get_main_menu_keyboard()
            )
            return
        
        keyboard = []
        for entry in entries:
            keyboard.append([InlineKeyboardButton(
                text=f"🔐 {entry['entry_name']}",
                callback_data=f"view_entry:{entry['id']}"
            )])
        
        keyboard.append([InlineKeyboardButton(
            text="⬅️ Back to Menu",
            callback_data="back_to_menu"
        )])
        
        entries_text = "\n".join([f"• {entry['entry_name']}" for entry in entries])
        
        await message.answer(
            f"📋 Your Password Entries:\n\n{entries_text}\n\n"
            "Select an entry to view or manage it.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard)
        )
        
    except Exception as e:
        logger.log_unexpected_error(e, "list_entries")
        await message.answer(
            "❌ An error occurred while retrieving your entries.", 
            reply_markup=get_main_menu_keyboard()
        )


@router.message(F.text == "➕ Add new entry")
async def add_new_entry(message: types.Message, state: FSMContext):
    """Initiate new password entry creation process."""
    try:
        user_id = message.from_user.id
        
        if not sessions.is_session_valid(user_id):
            await message.answer(
                "❌ Session expired. Please log in again.", 
                reply_markup=ReplyKeyboardRemove()
            )
            return
        
        from handlers.password_entry import PasswordState
        await message.answer(
            "📝 Create New Password Entry\n\n"
            "Please enter a name for this entry (e.g., 'Gmail', 'Facebook'):",
            reply_markup=get_back_to_menu_keyboard()
        )
        await state.set_state(PasswordState.waiting_for_entry_name)
        
    except Exception as e:
        logger.log_unexpected_error(e, "add_new_entry")
        await message.answer(
            "❌ An error occurred while starting entry creation.", 
            reply_markup=get_main_menu_keyboard()
        )


@router.message(F.text == "🔒 Logout")
async def logout_user(message: types.Message, state: FSMContext):
    """Log out user and clear session data."""
    try:
        user_id = message.from_user.id
        sessions.logout_user(user_id)
        
        await message.answer(
            "🔒 You have been logged out successfully.\n\n"
            "Your session has been cleared and all data is secure.",
            reply_markup=ReplyKeyboardRemove()
        )
        await state.clear()
        
        from handlers.auth import cmd_start
        await cmd_start(message, state)
        
    except Exception as e:
        logger.log_unexpected_error(e, "logout_user")
        await message.answer(
            "✅ Logged out successfully.", 
            reply_markup=ReplyKeyboardRemove()
        )
        await state.clear()


@router.message(F.text == "⬅️ Back to Menu")
async def back_to_menu(message: types.Message, state: FSMContext):
    """Return user to main menu."""
    await message.answer(
        "📱 Main Menu",
        reply_markup=get_main_menu_keyboard()
    )


@router.callback_query(F.data == "back_to_menu")
async def back_to_menu_callback(callback: types.CallbackQuery, state: FSMContext):
    """Handle back to menu action from inline callback."""
    await callback.message.edit_text(
        "📱 Main Menu",
        reply_markup=None
    )
    await callback.message.answer(
        "📱 Main Menu",
        reply_markup=get_main_menu_keyboard()
    )
    await callback.answer()