import sqlite3
import logging
from typing import Optional, List, Dict, Any
import os
import hashlib


class Database:
    """Database management class for password storage application."""
    
    def __init__(self, db_path: str = "db/passwords.db"):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.logger = logging.getLogger('db.database')
        self.init_db()

    def init_db(self):
        """Initialize database connection and create tables."""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            
            # Enable foreign keys
            self.cursor.execute("PRAGMA foreign_keys = ON")
            
            # Create tables
            self.create_tables()
            self.logger.info("Database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {str(e)}")
            raise

    def create_tables(self):
        """Create necessary tables if they don't exist."""
        # Users table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                encryption_key TEXT NOT NULL,
                telegram_id INTEGER NOT NULL
            )
        ''')
        
        # PasswordEntries table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS PasswordEntries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                entry_name TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                raw_blob TEXT,
                FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE CASCADE
            )
        ''')
        
        # BannedUsers table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS BannedUsers (
                telegram_id INTEGER PRIMARY KEY,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
        self.logger.info("Database tables created/verified successfully")

    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def is_user_banned(self, telegram_id: int) -> bool:
        """Check if user is banned."""
        try:
            self.cursor.execute(
                "SELECT telegram_id FROM BannedUsers WHERE telegram_id = ?",
                (telegram_id,)
            )
            return self.cursor.fetchone() is not None
        except Exception as e:
            self.logger.error(f"Error checking ban status: {str(e)}")
            return False

    def username_exists(self, username: str) -> bool:
        """Check if username already exists."""
        try:
            self.cursor.execute(
                "SELECT id FROM Users WHERE username = ?",
                (username,)
            )
            result = self.cursor.fetchone()
            return result is not None
        except Exception as e:
            self.logger.error(f"Error checking username existence: {str(e)}")
            return False

    def create_user(self, username: str, password_hash: str, encryption_key: str, telegram_id: int) -> bool:
        """Create a new user."""
        try:
            self.cursor.execute(
                "INSERT INTO Users (username, password_hash, encryption_key, telegram_id) VALUES (?, ?, ?, ?)",
                (username, password_hash, encryption_key, telegram_id)
            )
            self.conn.commit()
            self.logger.info(f"User created successfully: {username}")
            return True
        except sqlite3.IntegrityError:
            self.logger.warning(f"Username already exists: {username}")
            return False
        except Exception as e:
            self.logger.error(f"Error creating user: {str(e)}")
            return False

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        try:
            self.cursor.execute(
                "SELECT id, username, password_hash, encryption_key, telegram_id FROM Users WHERE username = ?",
                (username,)
            )
            result = self.cursor.fetchone()
            return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error getting user by username: {str(e)}")
            return None

    def get_user_by_telegram_id(self, telegram_id: int) -> Optional[Dict[str, Any]]:
        """Get user by telegram ID."""
        try:
            self.cursor.execute(
                "SELECT id, username, password_hash, encryption_key, telegram_id FROM Users WHERE telegram_id = ?",
                (telegram_id,)
            )
            result = self.cursor.fetchone()
            return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error getting user by telegram ID: {str(e)}")
            return None

    def create_password_entry(self, user_id: int, entry_name: str, email: str, password: str, raw_blob: str = None) -> bool:
        """Create a new password entry."""
        try:
            self.cursor.execute(
                "INSERT INTO PasswordEntries (user_id, entry_name, email, password, raw_blob) VALUES (?, ?, ?, ?, ?)",
                (user_id, entry_name, email, password, raw_blob)
            )
            self.conn.commit()
            self.logger.info(f"Password entry created for user ID: {user_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error creating password entry: {str(e)}")
            return False

    def get_password_entries(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all password entries for a user."""
        try:
            self.cursor.execute(
                "SELECT id, entry_name, email, password, raw_blob FROM PasswordEntries WHERE user_id = ? ORDER BY entry_name",
                (user_id,)
            )
            results = self.cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            self.logger.error(f"Error getting password entries: {str(e)}")
            return []

    def get_password_entry(self, entry_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific password entry by ID and user ID."""
        try:
            self.cursor.execute(
                "SELECT id, entry_name, email, password, raw_blob FROM PasswordEntries WHERE id = ? AND user_id = ?",
                (entry_id, user_id)
            )
            result = self.cursor.fetchone()
            return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error retrieving password entry {entry_id}: {str(e)}")
            return None

    def update_password_entry(self, entry_id: int, user_id: int, updates: dict) -> bool:
        """Update password entry with the provided fields."""
        try:
            if not updates:
                return False
                
            set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
            values = list(updates.values())
            values.extend([entry_id, user_id])
            
            query = f"UPDATE PasswordEntries SET {set_clause} WHERE id = ? AND user_id = ?"
            
            self.cursor.execute(query, values)
            self.conn.commit()
            
            return self.cursor.rowcount > 0
            
        except Exception as e:
            self.logger.error(f"Error updating password entry {entry_id}: {str(e)}")
            return False

    def delete_password_entry(self, entry_id: int, user_id: int) -> bool:
        """Delete a password entry."""
        try:
            self.cursor.execute(
                "DELETE FROM PasswordEntries WHERE id = ? AND user_id = ?",
                (entry_id, user_id)
            )
            self.conn.commit()
            return self.cursor.rowcount > 0
            
        except Exception as e:
            self.logger.error(f"Error deleting password entry {entry_id}: {str(e)}")
            return False

    def get_user_count(self) -> int:
        """Get total number of users."""
        try:
            self.cursor.execute("SELECT COUNT(*) FROM Users")
            return self.cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error retrieving user count: {str(e)}")
            return 0

    def get_password_entries_count(self) -> int:
        """Get total number of password entries."""
        try:
            self.cursor.execute("SELECT COUNT(*) FROM PasswordEntries")
            return self.cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error retrieving password entries count: {str(e)}")
            return 0

    def delete_user(self, identifier: str) -> bool:
        """Delete user by username or telegram ID."""
        try:
            # Try by telegram ID first (if it's numeric)
            if identifier.isdigit():
                self.cursor.execute("DELETE FROM Users WHERE telegram_id = ?", (int(identifier),))
            # Then try by username
            self.cursor.execute("DELETE FROM Users WHERE username = ?", (identifier,))
            
            self.conn.commit()
            return self.cursor.rowcount > 0
            
        except Exception as e:
            self.logger.error(f"Error deleting user {identifier}: {str(e)}")
            return False

    def ban_user(self, telegram_id: int, reason: str = "Violation of terms of service") -> bool:
        """Ban a user by telegram ID."""
        try:
            self.cursor.execute(
                "INSERT OR REPLACE INTO BannedUsers (telegram_id, reason) VALUES (?, ?)",
                (telegram_id, reason)
            )
            self.conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"Error banning user {telegram_id}: {str(e)}")
            return False

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


# Global database instance
db = Database()