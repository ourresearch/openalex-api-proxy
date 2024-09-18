import hashlib
import shortuuid
import json
import os
import re
from urllib.parse import urlparse
from datetime import datetime, timezone

import requests
from flask import abort, g, jsonify, make_response
from flask import request
from flask_limiter import Limiter
from werkzeug.http import http_date

from api_key import valid_key, get_all_valid_keys
from rate_limit_exempt_email import get_rate_limit_exempt_emails
from app import app
from app import elastic_api_url, formatter_api_url, ngrams_api_url, text_api_url, users_api_url
from app import logger
from app import memcached
from blocked_requester import check_for_blocked_requester

import sentry_sdk

API_POOL_PUBLIC = 'common'
API_POOL_POLITE = 'polite'
HIGH_RATE_LIMIT_API_KEYS = os.environ.get('HIGH_RATE_LIMIT_API_KEYS', '').split(';')
RATE_LIMIT_EXEMPT_EMAILS = os.environ.get('TOP_SECRET_UNLIMITED_EMAILS', '').split(';')

RATE_LIMIT_EXEMPT_EMAILS_FROM_DB = get_rate_limit_exempt_emails()
HIGH_RATE_LIMIT_API_KEYS_FROM_DB = get_all_valid_keys()


def abort_json(status_code, msg):
    body_dict = {
        "HTTP_status_code": status_code,
        "message": msg,
        "error": True
    }
    resp_string = json.dumps(body_dict, sort_keys=True, indent=4)
    resp = make_response(resp_string, status_code)
    resp.mimetype = "application/json"
    abort(resp)


def protect_updated_created_params(arg, arg_type):
    if arg_type == 'filter':
        pattern = r'(?:from|to)_(?:updated|created)_date:[><]?\d{4}-\d{2}-\d{2}'
    elif arg_type == 'sort':
        pattern = r'(?:from|to)_(?:updated|created)_date(?::(?:asc|desc))?'
    else:
        raise ValueError(f'arg_type {arg_type} is not supported')
    matches = re.findall(pattern, arg)
    if matches:
        matched_string = '", "'.join(matches)
        logger.debug(f'got {arg_type} with "{matched_string}"')
        if not g.api_key:
            abort_json(
                '403',
                f'you must include an api_key argument to use {matched_string} with {arg_type}'
            )
        elif not valid_key(g.api_key):
            abort_json('403', f'api_key {g.api_key} is expired or invalid')


def rate_limit_key():
    if g.api_pool == API_POOL_POLITE:
        return g.mailto
    elif g.api_key:
        return g.api_key
    else:
        return remote_address()


def rate_limit_value():
    if request.path and request.path.startswith('/text'):
        return '1/second, 1000/day'
    elif g.api_key and g.api_key in HIGH_RATE_LIMIT_API_KEYS:
        logger.debug(f'Authorized high rate limit for {g.app_request_id} due to API key.')
        return '100/second, 2000000/day'  # was '100/second, 1250000/day'. Increased to 2000000/day temporarily
    else:
        return '10/second, 100000/day'


def remote_address():
    if forwarded_for := request.headers.getlist('X-Forwarded-For'):
        return forwarded_for[0]
    else:
        return request.remote_addr


def request_mailto_address():
    mailto_address = None

    if arg_mailto := (request.args.get('mailto') or request.args.get('email')):
        mailto_address = arg_mailto
    elif from_header := request.headers.get('from'):
        mailto_address = from_header
    elif ua_header := request.headers.get('user-agent'):
        mailto_address = re.findall(r'mailto:([^);]*)|$', ua_header)[0].strip()

    # take anything that vaguely looks like an email address
    if mailto_address and re.match(r'^.+@.+\..+$', mailto_address):
        return mailto_address

    return None


def request_api_key():
    # first, look for "Authorization" header
    # Should be "Authorization: Bearer <api-key>"
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
    header_auth = request.headers.get('authorization')
    if header_auth:
        try:
            auth_type, api_key = header_auth.split(' ')
            if auth_type.lower() == 'bearer':
                return api_key
        except ValueError:
            logger.debug(f'invalid "authorization" header: {header_auth}')
            abort_json('400', f'invalid "authorization" header')

    # if not successful, look for the api key either in the url or the header
    return (
            request.args.get('api_key')
            or request.args.get('api-key')
            or request.headers.get('api_key')
            or request.headers.get('api-key')
    )


@app.before_request
def before_request():
    g.app_request_id = shortuuid.uuid()
    logger.debug(f'assigned request id {g.app_request_id}')

    g.api_key = request_api_key()

    if mailto := request_mailto_address():
        g.mailto = mailto
        g.api_pool = API_POOL_POLITE
    else:
        g.mailto = None
        g.api_pool = API_POOL_PUBLIC

    logger.info(f"url: {request.url}, mailto: {g.mailto}, api_key: {g.api_key}")

    logger.debug(f'{g.app_request_id}: assigned api pool {g.api_pool}')

    if blocked_requester := check_for_blocked_requester(request_ip=remote_address(), request_email=g.mailto):
        logger.info(json.dumps({'blocked_requester': blocked_requester.to_dict()}))

        return abort_json(
            403, f'{blocked_requester.email or blocked_requester.ip} is blocked. Please contact team@ourresearch.org.'
        )

    logger.debug(f'{g.app_request_id}: finished with before_request')


@app.after_request
def after_request(response):
    # support CORS
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS, PUT, DELETE, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control"
    response.headers["Access-Control-Expose-Headers"] = "Authorization, Cache-Control"
    response.headers["Access-Control-Allow-Credentials"] = "true"

    if response.status_code != 429:
        response.headers.pop('Retry-After', None)
        response.headers.pop('X-RateLimit-Limit', None)
        response.headers.pop('X-RateLimit-Remaining', None)
        response.headers.pop('X-RateLimit-Reset', None)
    else:
        if x_ratelimit_limit := response.headers.get('X-RateLimit-Limit'):
            try:
                response.headers['X-RateLimit-Limit'] = min(int(x_ratelimit_limit), 100000)
            except ValueError:
                pass

    if x_rate_limit_reset := response.headers.get('X-RateLimit-Reset'):
        try:
            response.headers['X-RateLimit-Reset'] = http_date(int(x_rate_limit_reset))
        except ValueError:
            pass

    try:
        response.headers['X-API-Pool'] = g.api_pool
    except AttributeError:
        pass

    if hasattr(g, "api_key") and g.api_key == os.environ.get('DEBUG_API_KEY', ''):
        # send message to sentry
        with sentry_sdk.push_scope() as scope:
            scope.set_extra("RATE_LIMIT_EXEMPT_EMAILS_FROM_DB", RATE_LIMIT_EXEMPT_EMAILS_FROM_DB)
            scope.set_extra("RATE_LIMIT_EXEMPT_EMAILS", RATE_LIMIT_EXEMPT_EMAILS)
            scope.set_extra("test4_in_exempt_emails_from_db", "test4@example.com" in RATE_LIMIT_EXEMPT_EMAILS_FROM_DB)
            scope.set_extra("test4_in_exempt_emails_from_env", "test4@example.com" in RATE_LIMIT_EXEMPT_EMAILS)
            sentry_sdk.capture_message("DEBUG API KEY MESSAGE - check ratelimit exempt emails")

    return response


limiter = Limiter(app, key_func=remote_address)

formatter_session = requests.Session()
elastic_session = requests.Session()
ngrams_session = requests.Session()
text_session = requests.Session()
user_session = requests.Session()


def select_worker_host(request_path, request_args):
    logger.debug(f'{g.app_request_id}: started_select_worker_host')
    group_by = request_args.get('group-by') or request_args.get('group_by')
    group_bys = request_args.get('group-bys') or request_args.get('group_bys')

    # /works/W2741809807.bib
    # /W2741809807.bib
    if re.match(r"^(?:works/+)?[wW]\d+\.bib$", request_path) and not request_args:
        return {'url': formatter_api_url, 'session': formatter_session}

    # /works?filter=title.search:science&format=csv or /works?filter=title.search:science&format=ris
    if re.match(r"^works/?", request_path):
        requested_format = request_args.get('format')
        if requested_format and requested_format.strip().lower() in ['csv', 'ris', 'wos-plaintext', 'zip'] and not group_by and not group_bys:
            return {'url': formatter_api_url, 'session': formatter_session}

    if re.match(r"^export/?", request_path):
        return {'url': formatter_api_url, 'session': formatter_session}

    if re.match(r"^text/?", request_path):
        return {'url': text_api_url, 'session': text_session}

    if re.match(r"^users/?", request_path):
        return {'url': users_api_url, 'session': user_session}

    # /works/W2548140242/ngrams or /works/10.1103/physrevlett.77.3865/ngrams
    if re.match(r"^works/[wW]\d+/ngrams/?$", request_path) or re.match(r"^works/10\..*/ngrams/?$", request_path):
        abort(404)  # ngrams no longer supported via API

    # everything else
    return {'url': elastic_api_url, 'session': elastic_session}


# request is exempt from rate limiting if this function returns True
# see https://flask-limiter.readthedocs.io/en/stable/api.html#flask_limiter.Limiter.request_filter
@limiter.request_filter
def email_rate_limit_exempt():
    return (g.mailto in RATE_LIMIT_EXEMPT_EMAILS) or (request.path and request.path.endswith('/ngrams'))


@app.route('/<path:request_path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@limiter.limit(limit_value=rate_limit_value, key_func=rate_limit_key)
def forward_request(request_path):
    logger.debug(f'{g.app_request_id}: started forward_request')

    worker_host = select_worker_host(request_path, request.args)
    logger.debug(f'{g.app_request_id}: got worker host {worker_host.get("url")}')

    # strip "users/" path prefix when forwarding to users api
    if 'user.openalex.org' in worker_host.get('url', ''):
        request_path = re.sub(r'^users/*', '', request_path)

    worker_url = f'{worker_host.get("url")}/{request_path}'

    worker_headers = dict(request.headers)
    if original_host_header := worker_headers.get('Host'):
        worker_headers['Host'] = re.sub('^[^:]*', urlparse(worker_url).hostname, original_host_header)

    worker_params = dict(request.args)

    # don't pass email or mailto args to elastic worker
    if worker_host.get("url") == elastic_api_url:
        try:
            del worker_params['email']
            del worker_params['mailto']
        except KeyError:
            pass

    logger.debug(f'{g.app_request_id}: calculated worker_params')

    if filter_arg := worker_params.get('filter'):
        protect_updated_created_params(filter_arg, 'filter')

    if sort_arg := worker_params.get('sort'):
        protect_updated_created_params(sort_arg, 'sort')

    worker_params.pop('api_key', None)

    logger.debug(f'{g.app_request_id}: authorized from_updated_date')

    cache_key = hashlib.sha256(
        json.dumps({'url': worker_url, 'args': worker_params}, sort_keys=True).encode('utf-8')
    ).hexdigest()

    response_source = 'cache'

    # if not (response_attrs := memcached.get(cache_key)):

    # disable caching
    if True:
        try:
            logger.debug(f'{g.app_request_id}: getting response from worker')

            if request.method != 'GET' and any([request.path.startswith(path) for path in {'/text', '/searches', '/users', '/test_stories'}]):
                session_method = getattr(worker_host.get('session'), request.method.lower())
                worker_response = session_method(worker_url, json=request.json,
                                                             headers=worker_headers,
                                                             allow_redirects=False)

            else:
                # bypass_cache automatically for certain endpoints
                if any([request.path.startswith(path) for path in {'/test_stories'}]):
                    worker_params.update({'bypass_cache': 'true'})
                worker_response = worker_host.get("session").get(worker_url,
                                                                 params=worker_params,
                                                                 headers=worker_headers,
                                                                 allow_redirects=False)
            response_source = worker_response.url

            response_attrs = {
                'status_code': worker_response.status_code,
                'content': worker_response.content,
                'headers': dict(worker_response.headers),
            }

            logger.debug(f'{g.app_request_id}: got response from worker')

        except requests.exceptions.RequestException:
            response_attrs = {
                'status_code': 500,
                'content': 'There was an error processing your request. Please try again.',
                'headers': {}
            }

    logger.debug(json.dumps(
        {
            'path': request_path,
            'args': worker_params,
            'response_source': response_source,
            'cache_key': cache_key,
            'response_status_code': response_attrs['status_code'],
            'api_pool': g.api_pool,
            'mailto': g.mailto,
            'remote_address': remote_address(),
            'request_id': g.app_request_id,
        }
    ))

    logger.debug(f'{g.app_request_id}: building proxy response from worker response')

    response = make_response(response_attrs['content'], response_attrs['status_code'])

    logger.debug(f'{g.app_request_id}: massaging proxy response headers')

    for k, v in response_attrs['headers'].items():
        k_low = k.lower()
        if (
            k_low == 'content-type'
            or k_low == 'content-disposition'
            or k_low.startswith('access-control-')
            or k_low == 'location'
        ):
            response.headers[k] = v

    logger.debug(f'{g.app_request_id}: returning proxy response from forward_request')

    return response


@app.route('/', methods=["GET", "POST"])
def base_endpoint():
    return jsonify({
        "version": "0.0.1",
        "documentation_url": "https://openalex.org/rest-api",
        "msg": "Don't panic"
    })

@app.route('/refreshdb', methods=["POST"])
def refreshdb():
    global RATE_LIMIT_EXEMPT_EMAILS_FROM_DB
    global HIGH_RATE_LIMIT_API_KEYS_FROM_DB
    RATE_LIMIT_EXEMPT_EMAILS_FROM_DB = get_rate_limit_exempt_emails()
    HIGH_RATE_LIMIT_API_KEYS_FROM_DB = get_all_valid_keys()
    return jsonify({"msg": "refresh successful", "sent_at": datetime.now(timezone.utc).isoformat()}), 200



if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
