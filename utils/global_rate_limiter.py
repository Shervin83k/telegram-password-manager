import time
from collections import defaultdict
from typing import Dict, Tuple


class GlobalRateLimiter:
    """Enhanced global rate limiter with request type differentiation."""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.limits = {
            'unauthenticated': 30,   # 30 requests per minute
            'authenticated': 100,    # 100 requests per minute  
            'sensitive': 20,         # 20 requests per minute
            'admin': 200             # 200 requests per minute
        }
        self.window = 60  # 1 minute time window
    
    def is_allowed(self, user_id: int, request_type: str = 'authenticated') -> Tuple[bool, str]:
        """Check if request is allowed based on rate limits.
        
        Args:
            user_id: User identifier
            request_type: Type of request being made
            
        Returns:
            Tuple of (allowed_status, message)
        """
        now = time.time()
        user_requests = self.requests[user_id]
        
        # Filter requests within current time window
        user_requests = [req for req in user_requests if now - req[0] < self.window]
        self.requests[user_id] = user_requests
        
        # Count requests of current type
        type_count = sum(1 for req_time, req_type in user_requests if req_type == request_type)
        limit = self.limits.get(request_type, self.limits['authenticated'])
        
        if type_count >= limit:
            time_until_reset = self.window - (now - user_requests[0][0]) if user_requests else self.window
            return False, f"Rate limit exceeded for {request_type} operations. Try again in {int(time_until_reset)} seconds."
        
        # Record current request
        user_requests.append((now, request_type))
        return True, ""
    
    def get_remaining_requests(self, user_id: int, request_type: str = 'authenticated') -> int:
        """Get remaining requests available for user in current time window.
        
        Args:
            user_id: User identifier
            request_type: Type of request being checked
            
        Returns:
            Number of remaining requests allowed
        """
        now = time.time()
        user_requests = self.requests[user_id]
        
        # Filter requests within current time window
        user_requests = [req for req in user_requests if now - req[0] < self.window]
        self.requests[user_id] = user_requests
        
        type_count = sum(1 for req_time, req_type in user_requests if req_type == request_type)
        limit = self.limits.get(request_type, self.limits['authenticated'])
        
        return max(0, limit - type_count)
    
    def get_request_stats(self, user_id: int) -> Dict[str, int]:
        """Get request statistics for user across all request types.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dictionary of request counts by type
        """
        now = time.time()
        user_requests = [req for req in self.requests[user_id] if now - req[0] < self.window]
        
        stats = {}
        for request_type in self.limits.keys():
            count = sum(1 for req_time, req_type in user_requests if req_type == request_type)
            stats[request_type] = count
        
        return stats
    
    def reset_user_limits(self, user_id: int):
        """Reset rate limits for specified user.
        
        Args:
            user_id: User identifier to reset limits for
        """
        if user_id in self.requests:
            del self.requests[user_id]


# Global rate limiter instance
global_limiter = GlobalRateLimiter()