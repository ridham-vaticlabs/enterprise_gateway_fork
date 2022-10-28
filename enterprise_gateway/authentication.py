import os
import time
from typing import Tuple, Any

from google.oauth2 import id_token
import google.auth
import google.auth.transport.requests
import requests

from requests.adapters import HTTPAdapter, Retry
from tornado import ioloop

import logging

logger = logging.getLogger(__name__)

# in seconds
AUTH_GROUP_EMAIL = os.environ["AUTH_GROUP_EMAIL"]
CLEANUP_FREQUENCY_SECONDS = 3600
EXPIRY_GRACE_PERIOD = 1200
NON_MEMBER_CACHE_PERIOD = 300

group_id = None

creds, _ = google.auth.default(
    scopes=["https://www.googleapis.com/auth/cloud-identity.groups.readonly"]
)

ci_lookup_url = (
    "https://content-cloudidentity.googleapis.com/v1/groups:lookup?groupKey.id={}"
)
ci_membership_check_url = "https://content-cloudidentity.googleapis.com/v1/{}/memberships:checkTransitiveMembership?query=member_key_id=={}"
token_cache = {}


def make_http_session() -> requests.Session:
    """ """
    session_object = requests.Session()
    retries = Retry(
        total=5, backoff_factor=0.1, status_forcelist=[429, 500, 502, 503, 504]
    )
    session_object.mount("http://", HTTPAdapter(max_retries=retries))
    session_object.mount("https://", HTTPAdapter(max_retries=retries))

    return session_object


def setup_group_name():
    """ """
    global group_id

    if not creds.valid:
        creds.refresh(google.auth.transport.requests.Request())

    session = make_http_session()
    response = session.get(
        ci_lookup_url.format(AUTH_GROUP_EMAIL),
        headers={"Authorization": f"Bearer {creds.token}"},
    )
    session.close()
    response = response.json()
    group_id = response["name"]


def cleanup_cache():
    """ """
    for key in list(token_cache.keys()):
        cache_val = token_cache.get(key, [])
        if len(cache_val) and is_expired(cache_val[3]):
            token_cache.pop(key, None)


def init_auth():
    """ """
    ioloop.PeriodicCallback(cleanup_cache, CLEANUP_FREQUENCY_SECONDS).start()
    setup_group_name()


def get_token_info(token: str) -> Tuple[Any, Any]:
    """ """

    response = id_token.verify_oauth2_token(
        token,
        google.auth.transport.requests.Request(session=make_http_session()),
        clock_skew_in_seconds=EXPIRY_GRACE_PERIOD,
    )
    if "email" in response:
        email = response["email"]
        expiry = float(response["exp"])
        return email, expiry

    return None, None


def is_expired(expiry: float) -> bool:
    """ """
    if expiry + EXPIRY_GRACE_PERIOD < time.time():
        return True

    return False


def get_membership(email_id: str) -> bool:
    """ """
    session = make_http_session()

    if not creds.valid:
        creds.refresh(google.auth.transport.requests.Request(session=session))

    session = make_http_session()
    response = session.get(
        ci_membership_check_url.format(group_id, email_id),
        headers={"Authorization": f"Bearer {creds.token}"},
    )
    response = response.json()
    return response.get("hasMembership", False)


def check_membership(token: str) -> bool:
    """ """
    try:
        if token in token_cache:
            value = token_cache[token]
            if value[1]:
                if not is_expired(value[2]):
                    return True
                else:
                    token_cache.pop(token)
                    return False
            else:
                if value[3] + NON_MEMBER_CACHE_PERIOD < time.time():
                    return False
                else:
                    token_cache.pop(token)

        email_id, expiry = get_token_info(token)

        if email_id and expiry and not is_expired(expiry):
            is_member = get_membership(email_id)
            token_cache[token] = (email_id, is_member, expiry, time.time())

            if is_member:
                return True

    except Exception:
        logger.exception("Error fetching membership info")

    return False
