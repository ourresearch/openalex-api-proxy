import hashlib
import shortuuid
import json
import os
import re
from urllib.parse import urlparse

import requests
from flask import abort, g, jsonify, make_response
from flask import request
from flask_limiter import Limiter
from werkzeug.http import http_date

from api_key import valid_key
from app import app
from app import elastic_api_url, formatter_api_url
from app import logger
from app import memcached
from blocked_requester import check_for_blocked_requester

API_POOL_PUBLIC = 'common'
API_POOL_POLITE = 'polite'
RATE_LIMIT_EXEMPT_EMAILS = os.environ.get('TOP_SECRET_UNLIMITED_EMAILS', '').split(';')


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


def rate_limit_key():
    if g.api_pool == API_POOL_POLITE:
        return g.mailto
    else:
        return remote_address()


def remote_address():
    if forwarded_for := request.headers.getlist('X-Forwarded-For'):
        return forwarded_for[0]
    else:
        return request.remote_addr


def request_mailto_address():
    mailto_address = None

    if arg_mailto := (request.args.get('mailto') or request.args.get('email')):
        mailto_address = arg_mailto
    elif ua_header := request.headers.get('user-agent'):
        mailto_address = re.findall(r'mailto:([^);]*)|$', ua_header)[0].strip()

    # take anything that vaguely looks like an email address
    if re.match(r'^.+@.+\..+$', mailto_address):
        return mailto_address

    return None


@app.before_request
def before_request():
    g.app_request_id = shortuuid.uuid()
    logger.info(f'assigned request id {g.app_request_id}')

    if mailto := request_mailto_address():
        g.mailto = mailto
        g.api_pool = API_POOL_POLITE
    else:
        g.mailto = None
        g.api_pool = API_POOL_PUBLIC

    logger.info(f'{g.app_request_id}: assigned api pool {g.api_pool}')

    if blocked_requester := check_for_blocked_requester(request_ip=remote_address(), request_email=g.mailto):
        logger.info(json.dumps({'blocked_requester': blocked_requester.to_dict()}))

        return abort_json(
            403, f'{blocked_requester.email or blocked_requester.ip} is blocked. Please contact team@ourresearch.org.'
        )

    logger.info(f'{g.app_request_id}: finished with before_request')


@app.after_request
def after_request(response):
    logger.info(f'{g.app_request_id}: starting after_request')
    logger.info(f'{g.app_request_id}: setting CORS headers')

    # support CORS
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS, PUT, DELETE, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control"
    response.headers["Access-Control-Expose-Headers"] = "Authorization, Cache-Control"
    response.headers["Access-Control-Allow-Credentials"] = "true"

    # make not cacheable because the GETs change after parameter change posts!
    response.cache_control.max_age = 0
    response.cache_control.no_cache = True

    logger.info(f'{g.app_request_id}: massaging rate limit headers')

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

    response.headers['X-API-Pool'] = g.api_pool

    logger.info(f'{g.app_request_id}: finished after_request, returning final response')

    return response


limiter = Limiter(app, key_func=remote_address)

formatter_session = requests.Session()
elastic_session = requests.Session()

def select_worker_host(request_path, request_args):
    logger.info(f'{g.app_request_id}: started_select_worker_host')

    # /works/W2741809807.bib
    # /W2741809807.bib
    if re.match(r"^(?:works/+)?[wW]\d+\.bib$", request_path) and not request_args:
        return {'url': formatter_api_url, 'session': formatter_session}

    # /works?filter=title.search:science&format=csv
    if re.match(r"^works/?", request_path) and request_args.get('format') == 'csv':
        return {'url': formatter_api_url, 'session': formatter_session}

    if re.match(r"^export/?", request_path):
        return {'url': formatter_api_url, 'session': formatter_session}

    # everything else
    return {'url': elastic_api_url, 'session': elastic_session}


@limiter.request_filter
def email_rate_limit_exempt():
    return g.mailto in RATE_LIMIT_EXEMPT_EMAILS


@app.route('/<path:request_path>', methods=['GET'])
@limiter.limit(limit_value='10/second', key_func=rate_limit_key)
@limiter.limit(limit_value='500000/day', key_func=rate_limit_key)
def forward_request(request_path):
    logger.info(f'{g.app_request_id}: started forward_request')

    # if g.api_pool == API_POOL_PUBLIC:
        # time.sleep(2)

    worker_host = select_worker_host(request_path, request.args)
    logger.info(f'{g.app_request_id}: got worker host {worker_host.get("url")}')
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

    logger.info(f'{g.app_request_id}: calculated worker_params')

    if filter_arg := worker_params.get('filter'):
        if matches := re.findall(r'(?:from_updated_date|from_created_date):\d{4}-\d{2}-\d{2}', filter_arg):
            logger.info(f'got from_updated/created_date filter "{matches[0]}"')

            if 'api_key' not in worker_params:
                abort_json('403', 'you must include an api_key argument to use from_updated_date')

            key = worker_params.pop('api_key')
            if not valid_key(key):
                abort_json('403', f'api_key {key} is expired or invalid')

    logger.info(f'{g.app_request_id}: authorized from_updated_date')

    cache_key = hashlib.sha256(
        json.dumps({'url': worker_url, 'args': worker_params}, sort_keys=True).encode('utf-8')
    ).hexdigest()

    response_source = 'cache'

    # if not (response_attrs := memcached.get(cache_key)):

    # disable caching
    if True:
        try:
            logger.info(f'{g.app_request_id}: getting response from worker')

            worker_response = worker_host.get("session").get(worker_url, params=worker_params, headers=worker_headers, allow_redirects=False)
            response_source = worker_response.url

            response_attrs = {
                'status_code': worker_response.status_code,
                'content': worker_response.content,
                'headers': dict(worker_response.headers),
            }

            logger.info(f'{g.app_request_id}: got response from worker')

            #if worker_response.status_code < 500:
                #memcached.set(cache_key, response_attrs)

        except requests.exceptions.RequestException:
            response_attrs = {
                'status_code': 500,
                'content': 'There was an error processing your request. Please try again.',
                'headers': {}
            }

    logger.info(json.dumps(
        {
            'path': request_path,
            'args': dict(request.args),
            'response_source': response_source,
            'cache_key': cache_key,
            'response_status_code': response_attrs['status_code'],
            'api_pool': g.api_pool,
            'mailto': g.mailto,
            'remote_address': remote_address(),
            'request_id': g.app_request_id,
        }
    ))

    logger.info(f'{g.app_request_id}: building proxy response from worker response')

    response = make_response(response_attrs['content'], response_attrs['status_code'])

    logger.info(f'{g.app_request_id}: massaging proxy response headers')

    for k, v in response_attrs['headers'].items():
        k_low = k.lower()
        if k_low == 'content-type' or k_low.startswith('access-control-') or k_low == 'location':
            response.headers[k] = v

    logger.info(f'{g.app_request_id}: returning proxy response from forward_request')

    return response


@app.route('/', methods=["GET", "POST"])
def base_endpoint():
    return jsonify({
        "version": "0.0.1",
        "documentation_url": "https://openalex.org/rest-api",
        "msg": "Don't panic"
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
