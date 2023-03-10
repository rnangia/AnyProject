import base64
import importlib
import json
import jwt
import random
import re
import string
import unicodedata
from calendar import timegm
from collections import OrderedDict
from datetime import datetime
from datetime import timedelta
from rest_framework_jwt.settings import api_settings as jwt_settings
from rest_framework import exceptions

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash, login as django_login, logout as django_logout
from django.contrib.sites.models import Site
from django.core.exceptions import FieldDoesNotExist, ImproperlyConfigured, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import ValidationError, validate_email
from django.db import models
from django.db.models import Q, FieldDoesNotExist, FileField
from django.db.models.fields import BinaryField, DateField, DateTimeField, EmailField, TimeField
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.utils import dateparse, six
from django.utils.http import int_to_base36, base36_to_int, is_safe_url, urlencode
from django.utils.encoding import force_bytes, force_text
from django.utils.six.moves.urllib.parse import urlsplit
from django.utils.translation import ugettext_lazy as _
from django.utils.timezone import now

from . import signals
from .exceptions import ImmediateHttpResponse
from .models import User, EmailAddress


# Magic number 7: if you run into collisions with this number, then you are
# of big enough scale to start investing in a decent user model...
MAX_USERNAME_SUFFIX_LENGTH = 7
USERNAME_SUFFIX_CHARS = (
    [string.digits] * 4 +
    [string.ascii_letters] * (MAX_USERNAME_SUFFIX_LENGTH - 4))
SERIALIZED_DB_FIELD_PREFIX = '_db_'


def email_address_exists(email):
    emailaddresses = EmailAddress.objects
    ret = emailaddresses.filter(email__iexact=email).exists()
    if not ret:
        users = User.objects
        ret = users.filter(**{'email__iexact': email}).exists()
    return ret

def get_username_max_length():
    max_length = User._meta.get_field('username').max_length
    return max_length

def valid_email_or_none(email):
    ret = None
    try:
        if email:
            validate_email(email)
            if len(email) <= EmailField().max_length:
                ret = email
    except ValidationError:
        pass
    return ret

def is_email_verified(request, email):
    """
    Checks whether or not the email address is already verified
    beyond allauth scope, for example, by having accepted an
    invitation before signing up.
    """
    ret = False
    verified_email = request.session.get('account_verified_email')
    if verified_email:
        ret = verified_email.lower() == email.lower()
    return ret

def cleanup_email_addresses(request, addresses):
    """
    Takes a list of EmailAddress instances and cleans it up, making
    sure only valid ones remain, without multiple primaries etc.
    Order is important: e.g. if multiple primary e-mail addresses
    exist, the first one encountered will be kept as primary.
    """
    # Let's group by `email`
    e2a = OrderedDict()  # maps email to EmailAddress
    primary_addresses = []
    verified_addresses = []
    primary_verified_addresses = []
    for address in addresses:
        # Pick up only valid ones...
        email = valid_email_or_none(address.email)
        if not email:
            continue
        # ... and non-conflicting ones...
        if (settings.UNIQUE_EMAIL and EmailAddress.objects.filter(email__iexact=email).exists()):
            continue
        a = e2a.get(email.lower())
        if a:
            a.primary = a.primary or address.primary
            a.verified = a.verified or address.verified
        else:
            a = address
            a.verified = a.verified or is_email_verified(request, a.email)
            e2a[email.lower()] = a
        if a.primary:
            primary_addresses.append(a)
            if a.verified:
                primary_verified_addresses.append(a)
        if a.verified:
            verified_addresses.append(a)
    # Now that we got things sorted out, let's assign a primary
    if primary_verified_addresses:
        primary_address = primary_verified_addresses[0]
    elif verified_addresses:
        # Pick any verified as primary
        primary_address = verified_addresses[0]
    elif primary_addresses:
        # Okay, let's pick primary then, even if unverified
        primary_address = primary_addresses[0]
    elif e2a:
        # Pick the first
        primary_address = e2a.keys()[0]
    else:
        # Empty
        primary_address = None
    # There can only be one primary
    for a in e2a.values():
        a.primary = primary_address.email.lower() == a.email.lower()
    return list(e2a.values()), primary_address


def setup_user_email(request, user, addresses):
    """
    Creates proper EmailAddress for the user that was just signed
    up. Only sets up, doesn't do any other handling such as sending
    out email confirmation mails etc.
    """  
    assert not EmailAddress.objects.filter(user=user).exists()
    priority_addresses = []
    # Is there a stashed e-mail?
    stashed_email = request.session.get('account_verified_email')
    if stashed_email:
        priority_addresses.append(EmailAddress(user=user, email=stashed_email, primary=True, verified=True))
    email = getattr(user, 'email')
    if email:
        priority_addresses.append(EmailAddress(user=user, email=email, primary=True, verified=False))
    addresses, primary = cleanup_email_addresses(request, priority_addresses + addresses)
    for a in addresses:
        a.user = user
        a.save()
    EmailAddress.objects.fill_cache_for_user(user, addresses)
    if (primary and email and email.lower() != primary.email.lower()):
        setattr(user, 'email', primary.email)
        user.save()
    return primary

def user_pk_to_url_str(user):
    """
    This should return a string.
    """
    if issubclass(type(User._meta.pk), models.UUIDField):
        if isinstance(user.pk, six.string_types):
            return user.pk
        return user.pk.hex

    ret = user.pk
    if isinstance(ret, six.integer_types):
        ret = int_to_base36(user.pk)
    return str(ret)    

def send_email_confirmation(request, user, signup=False):
    """
    E-mail verification mails are sent:
    a) Explicitly: when a user signs up
    b) Implicitly: when a user attempts to log in using an unverified
    e-mail while EMAIL_VERIFICATION is mandatory.
    Especially in case of b), we want to limit the number of mails
    sent (consider a user retrying a few times), which is why there is
    a cooldown period before sending a new mail. This cooldown period
    can be configured in ACCOUNT_EMAIL_CONFIRMATION_COOLDOWN setting.
    """

    cooldown_period = timedelta(seconds=settings.EMAIL_CONFIRMATION_COOLDOWN)

    email = getattr(user, 'email')
    if email:
        email_address = EmailAddress.objects.get_for_user(user, email)
        if not email_address.verified:
            print("email about to be verified")
            send_email = True
            email_address.send_confirmation(request, signup=signup)
        else:
            send_email = False

def get_login_redirect_url(request):
    """
    Returns the default URL to redirect to after logging in.  Note
    that URLs passed explicitly (e.g. by passing along a `next`
    GET parameter) take precedence over the value returned here.
    """
    assert request.user.is_authenticated
    url = getattr(settings, "LOGIN_REDIRECT_URLNAME", None)
    if url:
        warnings.warn("LOGIN_REDIRECT_URLNAME is deprecated, simply use LOGIN_REDIRECT_URL with a URL name", DeprecationWarning)
    else:
        url = settings.LOGIN_REDIRECT_URL
    return resolve_url(url)

def perform_login(request, user, email_verification, redirect_url=None, signal_kwargs=None, signup=False):
    """
    Keyword arguments:
    signup -- Indicates whether or not sending the
    email is essential (during signup), or if it can be skipped (e.g. in
    case email verification is optional and we are only logging in).
    """
    # Local users are stopped due to form validation checking
    # is_active, yet, adapter methods could toy with is_active in a
    # `user_signed_up` signal. Furthermore, social users should be
    # stopped anyway.
    print("in perform login")
    if not user.is_active:
        return HttpResponseRedirect(reverse('account_inactive'))

    has_verified_email = EmailAddress.objects.filter(user=user, verified=True).exists()
    if email_verification == 'NONE':
        pass
    elif email_verification == 'OPTIONAL':
        # In case of OPTIONAL verification: send on signup.
        if not has_verified_email and signup:
            send_email_confirmation(request, user, signup=signup)
    elif email_verification == 'MANDATORY':
        if not has_verified_email:
            return send_email_confirmation(request, user, signup=signup)
    try:
        django_login(request, user)
        response = HttpResponseRedirect(get_login_redirect_url(request))

#         if signal_kwargs is None:
#             signal_kwargs = {}
#         signals.user_logged_in.send(sender=user.__class__, request=request, response=response, user=user, **signal_kwargs)
#         message = render_to_string('account/messages/logged_in.txt', {'user': user}).strip()
#         if message:
#             messages.add_message(request, messages.SUCCESS, message)
    except ImmediateHttpResponse as e:
        response = e.response
    return response


def complete_signup(request, user, email_verification, success_url, signal_kwargs=None):
    print("in complete signup")
    if signal_kwargs is None:
        signal_kwargs = {}
    signals.user_signed_up.send(sender=user.__class__, request=request, user=user, **signal_kwargs)
    return perform_login(request, user, email_verification=email_verification, signup=True, redirect_url=success_url, signal_kwargs=signal_kwargs)


def jwt_encode(user):
    jwt_payload_handler = jwt_settings.JWT_PAYLOAD_HANDLER
    jwt_encode_handler = jwt_settings.JWT_ENCODE_HANDLER

    payload = dict({'user_id': user.pk, 'username': user.username, 'email': user.email, 'first_name': user.first_name, 'last_name': user.last_name}, **{'exp': datetime.utcnow() + timedelta(days=1),'orig_iat': timegm(datetime.utcnow().utctimetuple())})
    return jwt_encode_handler(payload)

def jwt_decode(token):
    jwt_decode_handler = jwt_settings.JWT_DECODE_HANDLER

    try:
        payload = jwt_decode_handler(token)
    except jwt.ExpiredSignature:
        raise exceptions.AuthenticationFailed(_('Signature has expired.'))
    except jwt.DecodeError:
        raise exceptions.AuthenticationFailed(_('Error decoding signature.'))
    except jwt.InvalidTokenError:
        raise exceptions.AuthenticationFailed()
        
    username = payload.get('username')
    return username

def build_absolute_uri(request, location, protocol=None):
    """request.build_absolute_uri() helper
    Like request.build_absolute_uri, but gracefully handling
    the case where request is None.
    """

    if request is None:
        site = Site.objects.get_current()
        bits = urlsplit(location)
        if not (bits.scheme and bits.netloc):
            uri = '{proto}://{domain}{url}'.format(proto=settings.DEFAULT_HTTP_PROTOCOL, domain=site.domain, url=location)
        else:
            uri = location
    else:
        uri = request.build_absolute_uri(location)
    # NOTE: We only force a protocol if we are instructed to do so
    # (via the `protocol` parameter, or, if the default is set to
    # HTTPS. The latter keeps compatibility with the debatable use
    # case of running your site under both HTTP and HTTPS, where one
    # would want to make sure HTTPS links end up in password reset
    # mails even while they were initiated on an HTTP password reset
    # form.
    if not protocol and settings.DEFAULT_HTTP_PROTOCOL == 'https':
        protocol = settings.DEFAULT_HTTP_PROTOCOL
    # (end NOTE)
    if protocol:
        uri = protocol + ':' + uri.partition(':')[2]
    return uri
