import logging
import os
import sys
import warnings
from urllib.parse import urlparse

import bmemcached
import limits.errors
import limits.util
import redis
from flask import Flask
from flask_compress import Compress
from flask_talisman import Talisman
from limits.storage.redis import RedisStorage
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import api_key
from apscheduler.schedulers.background import BackgroundScheduler

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(thread)d: %(message)s'
)

logger = logging.getLogger("openalex-api-proxy")

libraries_to_mum = [
    'psycopg2',
]

for library in libraries_to_mum:
    library_logger = logging.getLogger(library)
    library_logger.setLevel(logging.WARNING)
    library_logger.propagate = True
    warnings.filterwarnings("ignore", category=UserWarning, module=library)

sentry_sdk.init(dsn=os.environ.get("SENTRY_DSN"), integrations=[FlaskIntegration()])

app = Flask(__name__)
app.config['RATELIMIT_HEADERS_ENABLED'] = os.getenv('RATELIMIT_HEADERS_ENABLED')
app.config['RATELIMIT_STORAGE_URL'] = os.getenv('REDIS_URL')
app.config['RATELIMIT_HEADER_RETRY_AFTER_VALUE'] = 'http-date'
app.config['RATELIMIT_IN_MEMORY_FALLBACK_ENABLED'] = True
app.config['RATELIMIT_IN_MEMORY_FALLBACK'] = '100000/day'

elastic_api_url = os.getenv('ELASTIC_API_URL')
formatter_api_url = os.getenv('FORMATTER_API_URL')
ngrams_api_url = os.getenv('NGRAMS_API_URL')
text_api_url = os.getenv('TEXT_API_URL')
unpaywall_api_url = os.getenv('UNPAYWALL_API_URL')
users_api_url = os.getenv('USERS_API_URL')

Talisman(app, force_https=True)
Compress(app)

# Initialize scheduler for periodic tasks
scheduler = BackgroundScheduler()
scheduler.add_job(func=api_key.load_api_keys_from_csv, trigger="interval", minutes=5)
scheduler.start()

# Shut down the scheduler when exiting the app
import atexit
atexit.register(lambda: scheduler.shutdown())

def redis_init(self, uri: str, **options):
    """
    :param uri: uri of the form `redis://[:password]@host:port`,
     `redis://[:password]@host:port/db`,
     `rediss://[:password]@host:port`, `redis+unix:///path/to/sock` etc.
     This uri is passed directly to :func:`redis.from_url` except for the
     case of `redis+unix` where it is replaced with `unix`.
    :param options: all remaining keyword arguments are passed
     directly to the constructor of :class:`redis.Redis`
    :raise ConfigurationError: when the redis library is not available
    """
    redis_dependency = limits.util.get_dependency("redis")
    if not redis_dependency:
        raise limits.errors.ConfigurationError(
            "redis prerequisite not available"
        )  # pragma: no cover
    uri = uri.replace("redis+unix", "unix")

    redis_options = options.copy()
    parsed_redis_url = urlparse(uri)

    redis_options.update({
        'host': parsed_redis_url.hostname,
        'port': parsed_redis_url.port,
        'username': parsed_redis_url.username,
        'password': parsed_redis_url.password,
        'ssl': True,
        'ssl_cert_reqs': None
    })

    self.storage = redis.Redis(**redis_options)
    self.initialize_storage(uri)


RedisStorage.__init__ = redis_init

memcached_servers = os.environ.get('MEMCACHEDCLOUD_SERVERS', '').split(',')
memcached_username = os.environ.get('MEMCACHEDCLOUD_USERNAME')
memcached_password = os.environ.get('MEMCACHEDCLOUD_PASSWORD')

memcached = bmemcached.Client(
    memcached_servers,
    memcached_username,
    memcached_password
)
