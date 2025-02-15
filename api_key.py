from datetime import datetime, timezone

# Mock API keys with their associated metadata
API_KEYS = {
    'mock_key_1': {
        'email': 'user1@example.com',
        'created': '2025-01-01T00:00:00+00:00',
        'active': True,
        'expires': None,
        'is_demo': False
    },
    'mock_key_2': {
        'email': 'user2@example.com',
        'created': '2025-01-01T00:00:00+00:00',
        'active': True,
        'expires': None,
        'is_demo': False
    },
    'mock_demo_key': {
        'email': 'demo@example.com',
        'created': '2025-01-01T00:00:00+00:00',
        'active': True,
        'expires': '2026-01-01T00:00:00+00:00',
        'is_demo': True
    },
    'AmZLwHspecial': {  # Special high-rate-limit key
        'email': 'special@example.com',
        'created': '2025-01-01T00:00:00+00:00',
        'active': True,
        'expires': None,
        'is_demo': False
    }
}

def valid_key(key):
    """Check if an API key is valid."""
    if key not in API_KEYS:
        return False
    
    key_data = API_KEYS[key]
    if not key_data['active']:
        return False
        
    if key_data['expires']:
        expires = datetime.fromisoformat(key_data['expires'])
        if expires <= datetime.now(timezone.utc):
            return False
            
    return True

def get_all_valid_keys():
    """Get a list of all valid API keys."""
    return [key for key in API_KEYS.keys() if valid_key(key)]