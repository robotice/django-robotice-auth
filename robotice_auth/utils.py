
import datetime
import functools
import logging

from django.conf import settings
from django.contrib import auth
from django.contrib.auth import middleware
from django.contrib.auth import models
from django.utils import decorators
from django.utils import timezone

from six.moves.urllib import parse as urlparse


LOG = logging.getLogger(__name__)

_PROJECT_CACHE = {}

_TOKEN_TIMEOUT_MARGIN = getattr(settings, 'TOKEN_TIMEOUT_MARGIN', 0)

"""
We need the request object to get the user, so we'll slightly modify the
existing django.contrib.auth.get_user method. To do so we update the
auth middleware to point to our overridden method.

Calling the "patch_middleware_get_user" method somewhere like our urls.py
file takes care of hooking it in appropriately.
"""

from roboticeclient.common.horizon import HorizonClient
from roboticeclient.control.v1.base import RoboticeControlClient

# only change base client class
RoboticeControlClient.client_class = HorizonClient

robotice_client = RoboticeControlClient(type="control")

def middleware_get_user(request):
    if not hasattr(request, '_cached_user'):
        request._cached_user = get_user(request)
    return request._cached_user


def get_user(request):
    try:
        user_id = request.session[auth.SESSION_KEY]
        backend_path = request.session[auth.BACKEND_SESSION_KEY]
        backend = auth.load_backend(backend_path)
        backend.request = request
        user = backend.get_user(user_id) or models.AnonymousUser()
    except KeyError:
        user = models.AnonymousUser()
    return user


def patch_middleware_get_user():
    middleware.get_user = middleware_get_user
    auth.get_user = get_user


""" End Monkey-Patching. """


def is_token_valid(token, margin=None):
    """Timezone-aware checking of the auth token's expiration timestamp.

    Returns ``True`` if the token has not yet expired, otherwise ``False``.

    .. param:: token

       The openstack_auth.user.Token instance to check

    .. param:: margin

       A time margin in seconds to subtract from the real token's validity.
       An example usage is that the token can be valid once the middleware
       passed, and invalid (timed-out) during a view rendering and this
       generates authorization errors during the view rendering.
       A default margin can be set by the TOKEN_TIMEOUT_MARGIN in the
       django settings.
    """
    expiration = token.expires
    # In case we get an unparseable expiration timestamp, return False
    # so you can't have a "forever" token just by breaking the expires param.
    if expiration is None:
        return False
    if margin is None:
        margin = getattr(settings, 'TOKEN_TIMEOUT_MARGIN', 0)
    expiration = expiration - datetime.timedelta(seconds=margin)
    if settings.USE_TZ and timezone.is_naive(expiration):
        # Presumes that the Keystone is using UTC.
        expiration = timezone.make_aware(expiration, timezone.utc)
    return expiration > timezone.now()


# From django.contrib.auth.views
# Added in Django 1.4.3, 1.5b2
# Vendored here for compatibility with old Django versions.
def is_safe_url(url, host=None):
    """Return ``True`` if the url is a safe redirection.

    The safe redirection means that it doesn't point to a different host.
    Always returns ``False`` on an empty url.
    """
    if not url:
        return False
    netloc = urlparse.urlparse(url)[1]
    return not netloc or netloc == host


def memoize_by_keyword_arg(cache, kw_keys):
    """Memoize a function using the list of keyword argument name as its key.

    Wrap a function so that results for any keyword argument tuple are stored
    in 'cache'. Note that the keyword args to the function must be usable as
    dictionary keys.

    :param cache: Dictionary object to store the results.
    :param kw_keys: List of keyword arguments names. The values are used
                    for generating the key in the cache.
    """
    def _decorator(func):
        @functools.wraps(func, assigned=decorators.available_attrs(func))
        def wrapper(*args, **kwargs):
            mem_args = [kwargs[key] for key in kw_keys if key in kwargs]
            mem_args = '__'.join(str(mem_arg) for mem_arg in mem_args)
            if not mem_args:
                return func(*args, **kwargs)
            if mem_args in cache:
                return cache[mem_args]
            result = func(*args, **kwargs)
            cache[mem_args] = result
            return result
        return wrapper
    return _decorator


def remove_project_cache(token):
    _PROJECT_CACHE.pop(token, None)

def has_in_url_path(url, sub):
    """Test if the `sub` string is in the `url` path."""
    scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
    return sub in path


def url_path_replace(url, old, new, count=None):
    """Return a copy of url with replaced path.

    Return a copy of url with all occurrences of old replaced by new in the url
    path.  If the optional argument count is given, only the first count
    occurrences are replaced.
    """
    args = []
    scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
    if count is not None:
        args.append(count)
    return urlparse.urlunsplit((
        scheme, netloc, path.replace(old, new, *args), query, fragment))


def default_services_region(service_catalog, request=None):
    """Returns the first endpoint region for first non-identity service.

    Extracted from the service catalog.
    """
    if service_catalog:
        available_regions = [endpoint['region'] for service
                             in service_catalog for endpoint
                             in service['endpoints']
                             if service['type'] != 'identity']
        if not available_regions:
            # this is very likely an incomplete keystone setup
            LOG.warning('No regions could be found excluding identity.')
            available_regions = [endpoint['region'] for service
                                 in service_catalog for endpoint
                                 in service['endpoints']]
        if not available_regions:
            # this is a critical problem and it's not clear how this occurs
            LOG.error('No regions can be found in the service catalog.')
            return None
        selected_region = None
        if request:
            selected_region = request.COOKIES.get('services_region',
                                                  available_regions[0])
        if selected_region not in available_regions:
            selected_region = available_regions[0]
        return selected_region
    return None


def set_response_cookie(response, cookie_name, cookie_value):
    """a common policy of setting cookies for last used project
    and region, can be reused in other locations.
    this method will set the cookie to expire in 365 days.
    """
    now = timezone.now()
    expire_date = now + datetime.timedelta(days=365)
    response.set_cookie(cookie_name, cookie_value, expires=expire_date)
