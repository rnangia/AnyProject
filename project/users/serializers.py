from datetime import timedelta
import jwt
import logging
import requests

from django.conf import settings
from django.contrib.auth import authenticate, update_session_auth_hash
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode as uid_encoder, urlsafe_base64_decode as uid_decoder
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from rest_framework.exceptions import ValidationError

from .core import jwt_decode, get_username_max_length, email_address_exists, setup_user_email
from .models import User, EmailAddress, SocialAccount, SocialToken

logger = logging.getLogger('django')

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def _validate_username(self, username, password):
        user = None

        if username and password:
            user = authenticate(username=username, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def validate(self, attrs):
        username = attrs.get('email')
        password = attrs.get('password')

        user = self._validate_username(username, password)

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?

        if settings.EMAIL_VERIFICATION == 'MANDATORY':
            email_address = user.emailaddress_set.get(email=user.email)
            if not email_address.verified:
                raise serializers.ValidationError(_('E-mail is not verified.'))

        attrs['user'] = user
        return attrs


class UserDetailsSerializer(serializers.ModelSerializer):
    """
    User model w/o password
    """
    class Meta:
        model = User
        fields = ('pk', 'username', 'email', 'first_name', 'last_name')
        read_only_fields = ('email', )


class JWTSerializer(serializers.Serializer):
    """
    Serializer for JWT authentication.
    """
    token = serializers.CharField()
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
        """
        Required to allow using custom USER_DETAILS_SERIALIZER in
        JWTSerializer. Defining it here to avoid circular imports
        """
        user_data = UserDetailsSerializer(obj['user'], context=self.context).data
        return user_data


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    email = serializers.EmailField()

    def send_email(self, user):
        """
        Renders an e-mail to `email`.  `template_prefix` identifies the
        e-mail that is to be sent, e.g. "account/email/email_confirmation"
        """
        template_prefix = "email/password_reset"
        reset_url = "http://www.websitename.com:8000%s" % reverse_lazy("users:rest_password_reset_confirm", kwargs={'uidb64': uid_encoder(force_bytes(user.pk)).decode(), 'token': default_token_generator.make_token(user)})

        context = {
            'email': user.email,
            'reset_url': reset_url
        }

        subject = render_to_string('{0}_subject.txt'.format(template_prefix), context)
        # remove superfluous line breaks
        subject = " ".join(subject.splitlines()).strip()

        from_email = "no-reply@mail.websitename.com"

        template_name = '{0}_message.txt'.format(template_prefix)
        txt = render_to_string(template_name, context).strip()

        msg = {"from": from_email, "to": [user.email], "subject": subject, "text": txt}
        print(msg)
        return requests.post("https://api.mailgun.net/v3/mail.websitename.com/messages", auth=("api", settings.MAILGUN_SECRET_KEY), data=msg)

    def get_user(self, email):
        """Given an email, return matching user who should receive a reset.
        This allows subclasses to more easily customize the default policies
        that prevent inactive users and users with unusable passwords from
        resetting their password.
        """
        active_user = User.objects.get(email__iexact=email, is_active=True)
        return active_user if active_user.has_usable_password() else None

    def _validate_email(self, value):
        user = self.get_user(value)
        return user if user is not None else None

    def save(self):
        user = self._validate_email(self.validated_data['email'])
        if user is not None:
            self.send_email(user)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm

    def validate(self, attrs):
        self._errors = {}

        # Decode the uidb64 to uid to get User object
        try:
            uid = force_text(uid_decoder(attrs['uid']))
            self.user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise ValidationError({'uid': ['Invalid value']})

        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(user=self.user, data=attrs)
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs['token']):
            raise ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
        self.set_password_form.save()

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = settings.OLD_PASSWORD_FIELD_ENABLED
        self.logout_on_password_change = settings.LOGOUT_ON_PASSWORD_CHANGE

        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop('old_password')

        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            raise serializers.ValidationError('Invalid password')
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(user=self.user, data=attrs)

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()
        if not self.logout_on_password_change:
            update_session_auth_hash(self.request, self.user)

class RegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    captcha_token = serializers.CharField(required=True, write_only=True)

    def clean_password(self, password, user=None):
        """
        Validates a password. You can hook into this if you want to
        restrict the allowed password choices.
        """
        min_length = settings.PASSWORD_MIN_LENGTH
        if min_length and len(password) < min_length:
            raise forms.ValidationError(_("Password must be a minimum of {0} characters.").format(min_length))
        validate_password(password, user)
        return password

    def validate_email(self, email):
        if email and email_address_exists(email):
            raise serializers.ValidationError(_("A user is already registered with this e-mail address."))
        return email

    def validate_password1(self, password):
        return self.clean_password(password)

    def validate_captcha_token(self, value):
        try:
            r = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret': settings.RECAPTCHA_SECRET_KEY, 'response': value}, timeout=5)
            r.raise_for_status()

            json_response = r.json()
            print(json_response)
            if bool(json_response['success']):
                return value
            else:
                if 'error-codes' in json_response:
                    raise serializers.ValidationError(_('reCaptcha invalid or expired, try again'))
                else:
                    raise serializers.ValidationError(_('reCaptcha response from Google not valid, try again'))

        except requests.RequestException as e:
            raise ValidationError(_('Connection to reCaptcha server failed'))

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError(_("The two password fields didn't match."))
        return data

    def get_cleaned_data(self):
        return {
            'first_name': self.validated_data.get('first_name'),
            'last_name': self.validated_data.get('last_name'),
            'username': self.validated_data.get('email'),
            'email': self.validated_data.get('email'),
            'password1': self.validated_data.get('password1')
        }

    def save(self, request):
        cleaned_data = self.get_cleaned_data()

        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        email = cleaned_data.get('email')
        username = cleaned_data.get('username')
        password1 = cleaned_data.get('password1')

        user = User.objects.create_user(username, email)
        user.first_name = first_name
        user.last_name = last_name

        if password1 is not None:
            user.set_password(password1)
        else:
            user.set_unusable_password()
        user.save()

        setup_user_email(request, user, [])
        return user

class VerifyEmailSerializer(serializers.Serializer):
    key = serializers.CharField()

class SocialAccountSerializer(serializers.ModelSerializer):

    class Meta:
        model = SocialAccount
        fields = ('id', 'provider', 'uid', 'last_login', 'date_joined', )


class GoogleLoginSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, allow_blank=False)

    def parse_token(self, socialaccount, data):
        token = SocialToken(account=socialaccount, token=data['access_token'])
        token.token_secret = data.get('refresh_token', '')
        expires_in = data.get('expires_in', None)
        if expires_in:
            token.expires_at = timezone.now() + timedelta(seconds=int(expires_in))
        token.save()
        print(token)
        return token

    def check_if_email_exists(self, email):
        return User.objects.filter(email__iexact=email).exists()

    def check_if_social_exists(self, email):
        return SocialAccount.objects.filter(uid__iexact=email, provider=this.provider).exists()

    def sociallogin_from_response(self, data):

        username = data.get('email')
        email = data.get('email')
        last_name = data.get('family_name')
        first_name = data.get('given_name')
        email_verified = True if data.get('email_verified') == 'true' else False

        if not self.check_if_email_exists(email):
            user = User.objects.create_user(username, email)
            user.first_name = first_name
            user.last_name = last_name
            user.set_unusable_password()
            user.save()
            print(user)
            emailadd = EmailAddress(user=user, email=email, verified=True, primary=True)
            emailadd.save()
            socialaccount = SocialAccount(user=user, uid=email, provider=self.provider)
            socialaccount.save()
        elif self.check_if_social_exists(email):
            user = User.objects.get(email=email)
            socialaccount = SocialAccount.objects.get(uid=email, provider=self.provider)
        else:
            raise serializers.ValidationError(_("User is already registered with this e-mail address."))
        return (user, socialaccount)

    def complete_login(self, token, **kwargs):
        url = "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=%s" % token['id_token']
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        print("complete login", data)
        user = self.sociallogin_from_response(data)
        return user

    def get_access_token(self, code):
        data = {'redirect_uri': self.redirect_uri, 'grant_type': 'authorization_code', 'code': code, 'client_id': self.client_id, 'client_secret': self.client_secret}
        url = self.access_token_url
        resp = requests.post(url, data=data, headers=self.headers)
        access_token = None
        if resp.status_code == 200:
            access_token = resp.json()
            print(access_token)
        if not access_token or 'access_token' not in access_token:
            raise serializers.ValidationError(_('Error retrieving access token: %s' % resp.content))
        return access_token

    def validate(self, attrs):
        self.provider = 'google'
        self.client_id = settings.GOOGLE_IDENTITY_CLIENT_ID
        self.client_secret = settings.GOOGLE_IDENTITY_SECRET
        self.redirect_uri = "http://www.websitename.com/googleoauthcallback"
        self.access_token_url = 'https://www.googleapis.com/oauth2/v4/token'
        self.headers = None

        # Case 2: We received the authorization code
        if attrs.get('code'):
            code = attrs.get('code')
            scope = ['email', 'profile']
            token = self.get_access_token(code)
            access_token = token['access_token']
            print(access_token)
            user, socialaccount = self.complete_login(token)
            social_token = self.parse_token(socialaccount, token)
            attrs['user'] = user
        else:
            raise serializers.ValidationError(_("Incorrect input. code is required."))
        return attrs


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        logger.info("in validate")
        token = attrs.get('token')
        if token:
            username = jwt_decode(token)
            logger.info(username)
            user = User.objects.values('id', 'username', 'email', 'first_name', 'last_name', 'is_active').get(username=username)
            logger.info(user)
            if not user.get('is_active'):
                logger.info("user is not active")
                raise serializers.ValidationError(_("User account is disabled"))
            attrs['user'] = user
        else:
            raise serializers.ValidationError(_("Incorrect input. token is required."))
        return attrs
