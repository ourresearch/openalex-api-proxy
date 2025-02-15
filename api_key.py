from datetime import datetime, timezone

# Set of valid API keys
API_KEYS = {
    'mock_key_1',
    'mock_key_2',
    'mock_demo_key',
    'AmZLwHspecial'  # Special high-rate-limit key
}

def valid_key(key):
    """Check if an API key exists."""
    return key in API_KEYS

def get_all_valid_keys():
    """Get a list of all API keys."""
    return list(API_KEYS)