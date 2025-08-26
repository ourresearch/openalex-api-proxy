from datetime import datetime, timezone
import os
import csv
import requests
from io import StringIO
import time

import logging
logger = logging.getLogger("openalex-api-proxy")

# Dictionary of valid API keys with their rate limits
API_KEYS = {}

def load_api_keys_from_csv():
    """Load API keys from the CSV URL specified in environment variables."""
    csv_url = os.getenv('API_KEY_CSV_URL')
    if not csv_url:
        logger.error("API_KEY_CSV_URL environment variable not set")
        return

    logger.info(f"Starting to load API keys from {csv_url}")

    # Retry config
    MAX_RETRIES = 3
    BACKOFF_BASE = 1.0
    BACKOFF_CAP = 8.0
    TIMEOUT = (5, 30)

    try:
        response = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = requests.get(csv_url, timeout=TIMEOUT)
                response.raise_for_status()
                break  # success
            except Exception as e:
                logger.warning(f"Attempt {attempt}/{MAX_RETRIES} to fetch API keys failed: {e}")

                if attempt == MAX_RETRIES:
                    raise

                sleep_s = min(BACKOFF_BASE * (2 ** (attempt - 1)), BACKOFF_CAP)
                logger.info(f"Retrying in {sleep_s:.1f}s...")
                time.sleep(sleep_s)

        logger.info(f"Received CSV content (first 100 chars): {response.text[:100]}")

        API_KEYS.clear()

        csv_file = StringIO(response.text)
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            key = row.get('key', '').strip()
            if not key:  # Skip rows with missing keys
                continue
            try:
                calls_per_second = int(row.get('max per second', 0))
                calls_per_day = int(row.get('max per day', 0))  # using same value for both as shown in sample
                
                API_KEYS[key] = {
                    'calls_per_second': calls_per_second,
                    'calls_per_day': calls_per_day
                }
            except (ValueError, TypeError) as e:
                logger.error(f"Error parsing rate limits for key {key}: {e}")
                continue

        logger.info(f"Successfully loaded {len(API_KEYS)} API keys")
        logger.info(f"First few keys loaded: {list(API_KEYS.keys())[:5]}")

    except Exception as e:
        logger.error(f"Error loading API keys from CSV: {e}")
        if isinstance(e, requests.RequestException):
            logger.error(f"Request error details: {e.response.text if e.response else 'No response'}")

def valid_key(key):
    """Check if an API key exists."""
    is_valid = key in API_KEYS
    logger.info(f"Checking key {key}: {'valid' if is_valid else 'invalid'}")
    return is_valid

def get_rate_limits(key):
    """Get rate limits for a key. Returns default limits if key doesn't exist."""
    if key in API_KEYS:
        limits = API_KEYS[key]
        limit_str = f"{limits['calls_per_second']}/second, {limits['calls_per_day']}/day"
        logger.info(f"Returning limits for key {key}: {limit_str}")
        return limit_str

    logger.warning(f"Key {key} not found, returning default limits")
    return "10/second, 100000/day"  # default limits for invalid/missing keys

def get_all_valid_keys():
    """Get a list of all API keys."""
    return list(API_KEYS.keys())

# Load keys when module is imported
load_api_keys_from_csv()