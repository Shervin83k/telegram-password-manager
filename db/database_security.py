import logging
import sqlite3
from typing import Any, List, Dict, Optional
from utils.validators import InputValidator

logger = logging.getLogger(__name__)


class DatabaseSecurity:
    """Security wrapper for database operations with comprehensive error handling."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def safe_execute(self, query: str, params: tuple = (), operation: str = "unknown") -> bool:
        """Execute query with comprehensive error handling and logging."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.IntegrityError as e:
            logger.warning(f"Database integrity error in {operation}: {e}")
            return False
        except sqlite3.OperationalError as e:
            logger.error(f"Database operational error in {operation}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected database error in {operation}: {e}")
            return False
    
    def safe_fetchone(self, query: str, params: tuple = (), operation: str = "unknown") -> Optional[Dict[str, Any]]:
        """Safely fetch single record with error handling."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone()
            conn.close()
            
            return dict(result) if result else None
            
        except Exception as e:
            logger.error(f"Error fetching record in {operation}: {e}")
            return None
    
    def safe_fetchall(self, query: str, params: tuple = (), operation: str = "unknown") -> List[Dict[str, Any]]:
        """Safely fetch all records with error handling."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Error fetching records in {operation}: {e}")
            return []
    
    def validate_user_input(self, input_data: str, input_type: str) -> bool:
        """Validate user input before database operations."""
        if input_type == "username":
            is_valid, _ = InputValidator.validate_username(input_data)
            return is_valid
        elif input_type == "entry_name":
            is_valid, _ = InputValidator.validate_entry_name(input_data)
            return is_valid
        elif input_type == "email":
            is_valid, _ = InputValidator.validate_email(input_data)
            return is_valid
        else:
            sanitized = InputValidator.sanitize_input(input_data)
            return len(sanitized) > 0