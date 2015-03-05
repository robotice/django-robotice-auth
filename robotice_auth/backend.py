
""" Module defining the Django auth backend class for the Robotice API. """

import logging

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from roboticeclient import exceptions as robotice_exceptions

from robotice_auth import exceptions

from robotice_auth import user as auth_user

from robotice_auth.utils import robotice_client
from robotice_auth import utils


LOG = logging.getLogger(__name__)


class RoboticeBackend(object):
    """Django authentication backend class for use with
      ``django.contrib.auth``.
    """

    def check_auth_expiry(self, auth_ref, margin=None):
        if not utils.is_token_valid(auth_ref, margin):
            msg = _("The authentication token issued by the Identity service "
                    "has expired.")
            LOG.warning("The authentication token issued by the Identity "
                        "service appears to have expired before it was "
                        "issued. This may indicate a problem with either your "
                        "server or client configuration.")
            raise robotice_exceptions.AuthException(msg)
        return True

    def get_user(self, user_id):
        """Returns the current user (if authenticated) based on the user ID
        and session data.

        Note: this required monkey-patching the ``contrib.auth`` middleware
        to make the ``request`` object available to the auth backend class.
        """
        if hasattr(self, 'request') and user_id:
            if hasattr(self, "user") and self.user.is_authenticated():
                return self.user
            token = self.request.session['token']
            user = self.request.session['user']
            if user:
                return user
            else:
                # TODO: do more
                #user = auth_user.create_user_from_token(self.request, token)
                pass
            return user
        else:
            return None

    def authenticate(self, request=None, username=None, password=None,
                     user_domain_name=None, auth_url=None):
        """Authenticates a user via the Keystone Identity API."""
        LOG.debug('Beginning user authentication for user "%s".' % username)

        try:
            auth_data = {
                "username": username,
                "password": password
            }
            unscoped_auth = robotice_client.auth.login(request, auth_data)
        except (robotice_exceptions.Unauthorized,
                robotice_exceptions.BadRequest) as exc:
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            LOG.debug(str(exc))
            raise exceptions.RoboticeAuthException(msg)
        try:
            # If we made it here we succeeded. Create our User!
            user = auth_user.create_user_from_token(auth_ref=unscoped_auth)
            auth_user.set_session_from_user(request, user)
        except Exception, e:
            raise e

        if request is not None:
            request.user = user
        self.user = user
        LOG.debug('Authentication completed for user "%s".' % username)
        return user

    def get_group_permissions(self, user, obj=None):
        """Returns an empty set since Keystone doesn't support "groups"."""
        # Keystone V3 added "groups". The Auth token response includes the
        # roles from the user's Group assignment. It should be fine just
        # returning an empty set here.
        return set()

    def get_all_permissions(self, user, obj=None):
        """Returns a set of permission strings that this user has through
           his/her Keystone "roles".

          The permissions are returned as ``"openstack.{{ role.name }}"``.
        """
        if user.is_anonymous() or obj is not None:
            return set()

        role_perms = set(["robotice.roles.%s" % role['name'].lower()
                          for role in user.roles])
        return role_perms

    def has_perm(self, user, perm, obj=None):
        """Returns True if the given user has the specified permission."""
        if not user.is_active:
            return False
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        """Returns True if user has any permissions in the given app_label.

           Currently this matches for the app_label ``"openstack"``.
        """
        if not user.is_active:
            return False
        for perm in self.get_all_permissions(user):
            if perm[:perm.index('.')] == app_label:
                return True
        return False
