import logging
import sqlite3
import os
import sys
import time
from typing import List, Dict, Any

# Add current directory to Python path for module imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from db.database import Database
    from config import DB_PATH
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("📁 Please execute from main project directory")
    sys.exit(1)

logger = logging.getLogger(__name__)


class AdminPanel:
    """Administrative interface for bot management and monitoring."""
    
    def __init__(self):
        self.db_path = DB_PATH
        self.db = Database(self.db_path)
    
    def get_bot_stats(self) -> Dict[str, Any]:
        """Retrieve comprehensive bot statistics.
        
        Returns:
            Dictionary containing user counts, entry counts, and system metrics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM Users")
                user_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM PasswordEntries")
                entries_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM BannedUsers")
                banned_count = cursor.fetchone()[0]
                
                db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                
                return {
                    'users': user_count,
                    'entries': entries_count,
                    'banned_users': banned_count,
                    'db_size_mb': round(db_size / (1024 * 1024), 2)
                }
                
        except Exception as e:
            logger.error(f"Statistics retrieval failed: {e}")
            return {'users': 0, 'entries': 0, 'banned_users': 0, 'db_size_mb': 0}
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Retrieve all registered users with entry counts.
        
        Returns:
            List of user dictionaries with comprehensive information
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT u.id, u.username, u.telegram_id, u.created_at,
                           COUNT(p.id) as entry_count
                    FROM Users u
                    LEFT JOIN PasswordEntries p ON u.id = p.user_id
                    GROUP BY u.id
                    ORDER BY u.created_at DESC
                ''')
                
                users = []
                for row in cursor.fetchall():
                    user_dict = dict(row)
                    if user_dict['created_at']:
                        user_dict['created_at'] = user_dict['created_at'].split('.')[0]
                    users.append(user_dict)
                
                return users
                
        except Exception as e:
            print(f"❌ User retrieval error: {e}")
            return []
    
    def delete_user(self, identifier: str) -> bool:
        """Remove user by username or Telegram ID.
        
        Args:
            identifier: Username string or Telegram ID number
            
        Returns:
            Boolean indicating successful deletion
        """
        try:
            if identifier.isdigit():
                telegram_id = int(identifier)
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM Users WHERE telegram_id = ?", (telegram_id,))
                    user = cursor.fetchone()
                    if user:
                        cursor.execute("DELETE FROM Users WHERE telegram_id = ?", (telegram_id,))
                        conn.commit()
                        return cursor.rowcount > 0
            else:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM Users WHERE username = ?", (identifier,))
                    conn.commit()
                    return cursor.rowcount > 0
            return False
        except Exception as e:
            print(f"❌ User deletion error: {e}")
            return False
    
    def ban_user(self, telegram_id: int, reason: str = "No reason provided") -> bool:
        """Ban user from bot access.
        
        Args:
            telegram_id: User's Telegram identifier
            reason: Explanation for ban action
            
        Returns:
            Boolean indicating successful ban
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO BannedUsers (telegram_id, reason) VALUES (?, ?)",
                    (telegram_id, reason)
                )
                conn.commit()
                return True
        except Exception as e:
            print(f"❌ User ban error: {e}")
            return False
    
    def unban_user(self, telegram_id: int) -> bool:
        """Remove user from banned list.
        
        Args:
            telegram_id: User's Telegram identifier
            
        Returns:
            Boolean indicating successful unban
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM BannedUsers WHERE telegram_id = ?", (telegram_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"❌ User unban error: {e}")
            return False
    
    def get_banned_users(self) -> List[Dict[str, Any]]:
        """Retrieve list of all banned users.
        
        Returns:
            List of banned user dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT telegram_id, reason, banned_at FROM BannedUsers")
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Banned users retrieval error: {e}")
            return []


def display_admin_menu():
    """Display administrative control panel interface."""
    print("\n" + "="*50)
    print("🔧 Password Manager Bot - Administrative Panel")
    print("="*50)
    print("1. 📊 System Statistics")
    print("2. 👥 User Management")
    print("3. 🚫 Banned Users")
    print("4. 🗑️ Remove User")
    print("5. 🚫 Restrict User")
    print("6. ✅ Reinstate User")
    print("7. 📜 System Logs")
    print("8. 🚪 Exit Panel")
    print("="*50)


def clear_screen():
    """Clear terminal display for clean interface."""
    os.system('cls' if os.name == 'nt' else 'clear')


def run_admin_panel():
    """Execute administrative panel main loop."""
    try:
        admin_panel = AdminPanel()
        print("✅ Administrative panel initialized")
        print(f"📁 Database path: {DB_PATH}")
    except Exception as e:
        print(f"❌ Panel initialization failed: {e}")
        return
    
    while True:
        clear_screen()
        display_admin_menu()
        try:
            choice = input("\nSelect option (1-8): ").strip()
        except KeyboardInterrupt:
            print("\n\n👋 Administrative panel terminated")
            break
        
        if choice == "1":
            stats = admin_panel.get_bot_stats()
            print(f"\n📊 System Statistics:")
            print(f"   👥 Registered Users: {stats['users']}")
            print(f"   🔐 Password Entries: {stats['entries']}")
            print(f"   🚫 Restricted Users: {stats['banned_users']}")
            print(f"   💾 Database Size: {stats['db_size_mb']} MB")
            
        elif choice == "2":
            users = admin_panel.get_all_users()
            print(f"\n👥 User Registry ({len(users)} users):")
            if users:
                for i, user in enumerate(users, 1):
                    print(f"\n   {i}. 📝 {user['username']}")
                    print(f"      🆔 Telegram ID: {user['telegram_id']}")
                    print(f"      📂 Stored Entries: {user['entry_count']}")
                    print(f"      📅 Registration: {user['created_at']}")
            else:
                print("   No registered users")
                
        elif choice == "3":
            banned_users = admin_panel.get_banned_users()
            print(f"\n🚫 Restricted Users ({len(banned_users)} total):")
            if banned_users:
                for user in banned_users:
                    print(f"   🆔 {user['telegram_id']} - Reason: {user['reason']}")
                    print(f"      Restricted: {user['banned_at']}")
            else:
                print("   No restricted users")
                
        elif choice == "4":
            identifier = input("Enter username or Telegram ID: ").strip()
            if identifier:
                if admin_panel.delete_user(identifier):
                    print(f"✅ User '{identifier}' removed successfully")
                else:
                    print(f"❌ Removal failed for '{identifier}'")
            else:
                print("❌ No identifier provided")
                
        elif choice == "5":
            try:
                telegram_id = int(input("Enter Telegram ID: ").strip())
                reason = input("Restriction reason: ").strip() or "No reason provided"
                if admin_panel.ban_user(telegram_id, reason):
                    print(f"✅ User {telegram_id} restricted")
                else:
                    print(f"❌ Restriction failed for {telegram_id}")
            except ValueError:
                print("❌ Invalid Telegram ID")
                
        elif choice == "6":
            try:
                telegram_id = int(input("Enter Telegram ID: ").strip())
                if admin_panel.unban_user(telegram_id):
                    print(f"✅ User {telegram_id} reinstated")
                else:
                    print(f"❌ Reinstatement failed for {telegram_id}")
            except ValueError:
                print("❌ Invalid Telegram ID")
                
        elif choice == "7":
            print("\n📜 System Logs (Ctrl+C to exit):")
            print("="*50)
            try:
                log_file = "bot.log"
                if os.path.exists(log_file):
                    with open(log_file, "r", encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines[-20:]:
                            print(line.strip())
                    
                    print("\n🔍 Monitoring new entries...")
                    with open(log_file, "r", encoding='utf-8') as f:
                        f.seek(0, 2)
                        while True:
                            line = f.readline()
                            if line:
                                print(line.strip())
                            time.sleep(0.1)
                else:
                    print("❌ Log file unavailable")
            except KeyboardInterrupt:
                print("\n⏹️ Log monitoring ended")
                
        elif choice == "8":
            print("👋 Administrative panel closed")
            break
            
        else:
            print("❌ Invalid selection")
        
        if choice != "7":
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    print("🚀 Starting Administrative Panel...")
    run_admin_panel()