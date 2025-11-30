import time
from collections import defaultdict
from typing import Dict, Tuple


class RateLimiter:
    """Rate limiting implementation for security and abuse prevention."""
    
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[int, list] = defaultdict(list)
    
    def is_rate_limited(self, user_id: int) -> Tuple[bool, str]:
        """Check if user has exceeded rate limits.
        
        Args:
            user_id: User identifier to check
            
        Returns:
            Tuple of (is_limited, message)
        """
        now = time.time()
        user_attempts = self.attempts[user_id]
        
        # Filter attempts within current time window
        user_attempts = [attempt for attempt in user_attempts if now - attempt < self.window_seconds]
        self.attempts[user_id] = user_attempts
        
        if len(user_attempts) >= self.max_attempts:
            time_left = int(self.window_seconds - (now - user_attempts[0]))
            return True, f"Rate limit exceeded. Please try again in {time_left} seconds."
        
        return False, ""
    
    def record_attempt(self, user_id: int):
        """Record an attempt for the specified user.
        
        Args:
            user_id: User identifier to record attempt for
        """
        self.attempts[user_id].append(time.time())
    
    def reset_attempts(self, user_id: int):
        """Clear all attempts for the specified user.
        
        Args:
            user_id: User identifier to reset attempts for
        """
        if user_id in self.attempts:
            self.attempts[user_id] = []


# Global rate limiter instance for login attempts
login_limiter = RateLimiter(max_attempts=5, window_seconds=300)