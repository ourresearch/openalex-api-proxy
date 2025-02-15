from datetime import datetime, timezone

# Dictionary of valid API keys with their rate limits
API_KEYS = {
    'mock_key_1': {
        'calls_per_second': 100,
        'calls_per_day': 2000000
    },
    'mock_key_2': {
        'calls_per_second': 100,
        'calls_per_day': 2000000
    },
    'mock_demo_key': {
        'calls_per_second': 10,
        'calls_per_day': 100000
    },
    'AmZLwHspecial': {  # Special high-rate-limit key
        'calls_per_second': 100,
        'calls_per_day': 4000000
    }
}

def valid_key(key):
    """Check if an API key exists."""
    return key in API_KEYS

def get_rate_limits(key):
    """Get rate limits for a key. Returns default limits if key doesn't exist."""
    if key in API_KEYS:
        limits = API_KEYS[key]
        return f"{limits['calls_per_second']}/second, {limits['calls_per_day']}/day"
    return "10/second, 100000/day"  # default limits for invalid/missing keys

def get_all_valid_keys():
    """Get a list of all API keys."""
    return list(API_KEYS.keys())