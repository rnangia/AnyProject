import requests
import datetime
from phonenumber_field.modelfields import PhoneNumberField

from django.conf import settings
from django.contrib.auth import authenticate
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.contrib.auth.models import AbstractUser
from django.contrib.sites.models import Site
from django.contrib.sites.shortcuts import get_current_site
from django.db import models, transaction
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from .fields import JSONField
from .managers import EmailAddressManager
from . import signals


class User(AbstractUser):
    phone_number = PhoneNumberField(_("Phone number"), blank=True, help_text=_("In case we need to call you about your order"))


class EmailAddress(models.Model):
    user = models.ForeignKey(User, verbose_name=_('user'), on_delete=models.CASCADE)
    email = models.EmailField(unique=True, max_length=settings.EMAIL_MAX_LENGTH, verbose_name=_('e-mail address'))
    verified = models.BooleanField(verbose_name=_('verified'), default=False)
    primary = models.BooleanField(verbose_name=_('primary'), default=False)

    objects = EmailAddressManager()

    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")
        if not settings.UNIQUE_EMAIL:
            unique_together = [("user", "email")]

    def __str__(self):
        return "%s (%s)" % (self.email, self.user)

    def set_as_primary(self, conditional=False):
        old_primary = EmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        self.primary = True
        self.save()
        self.user.save()
        return True

    def send_confirmation(self, request=None, signup=False):
        print("in send confirmation")
        confirmation = EmailConfirmationHMAC(self)
        confirmation.send(request, signup=signup)
        return confirmation

    def change(self, request, new_email, confirm=True):
        """
        Given a new email address, change self and re-confirm.
        """
        with transaction.atomic():
            self.user.save()
            self.email = new_email
            self.verified = False
            self.save()
            if confirm:
                self.send_confirmation(request)

class EmailConfirmationHMAC:

    def __init__(self, email_address):
        self.email_address = email_address

    @property
    def key(self):
        return signing.dumps(obj=self.email_address.pk, salt=settings.SALT)

    @classmethod
    def from_key(cls, key):
        try:
            max_age = (60 * 60 * 24 * settings.EMAIL_CONFIRMATION_EXPIRE_DAYS)
            pk = signing.loads(key, max_age=max_age, salt=settings.SALT)
            ret = EmailConfirmationHMAC(EmailAddress.objects.get(pk=pk))
        except (signing.SignatureExpired, signing.BadSignature, EmailAddress.DoesNotExist):
            ret = None
        return ret

    def confirm_email(self, request, email_address):
        """
        Marks the email address as confirmed on the db
        """
        email_address.verified = True
        email_address.set_as_primary(conditional=True)
        email_address.save()

    def format_email_subject(self, subject):
        prefix = settings.EMAIL_SUBJECT_PREFIX
        if prefix is None:
#             site = get_current_site(self.request)
#             prefix = "[{name}] ".format(name=site.name)
            prefix = "[{name}] ".format(name="fuchsiarama")
        return prefix + force_text(subject)

    def get_email_confirmation_url(self, request, emailconfirmation):
        """Constructs the email confirmation (activation) url.
        Note that if you have architected your system such that email
        confirmations are sent outside of the request context `request`
        can be `None` here.
        """
        url = reverse_lazy("users:rest_verify_email", args=[emailconfirmation.key])
        ret = "https://www.websitename.com:8000%s" % url
        print(ret)
        return ret

    def render_mail(self, template_prefix, email, context):
        """
        Renders an e-mail to `email`.  `template_prefix` identifies the
        e-mail that is to be sent, e.g. "account/email/email_confirmation"
        """
        print("in render mail")
        subject = render_to_string('{0}_subject.txt'.format(template_prefix), context)
        # remove superfluous line breaks
        subject = " ".join(subject.splitlines()).strip()
        subject = self.format_email_subject(subject)

        from_email = "no-reply@mail.websitename.com"

        template_name = '{0}_message.txt'.format(template_prefix)
        txt = render_to_string(template_name, context).strip()

        msg = {"from": from_email, "to": [email], "subject": subject, "text": txt}
        print(msg)
        return msg

    def send_mail(self, template_prefix, email, context):
        msg = self.render_mail(template_prefix, email, context)
        print("in send mail")
        return requests.post("https://api.mailgun.net/v3/mail.websitename.com/messages", auth=("api", settings.MAILGUN_SECRET_KEY), data=msg)

    def send_confirmation_mail(self, request, emailconfirmation, signup):
        current_site = get_current_site(request)
        activate_url = self.get_email_confirmation_url(request, emailconfirmation)
        ctx = {
            "user": emailconfirmation.email_address.user,
            "activate_url": activate_url,
            "current_site": current_site,
            "key": emailconfirmation.key,
        }
        email_template = 'email/confirmation_signup'
        self.send_mail(email_template, emailconfirmation.email_address.email, ctx)

    def confirm(self, request):
        if not self.email_address.verified:
            email_address = self.email_address
            self.confirm_email(request, email_address)
            signals.email_confirmed.send(sender=self.__class__, request=request, email_address=email_address)
            return email_address

    def send(self, request=None, signup=False):
        self.send_confirmation_mail(request, self, signup)
        signals.email_confirmation_sent.send(sender=self.__class__, request=request, confirmation=self, signup=signup)



class SocialAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    provider_choices = (('google', 'Google'))
    provider = models.CharField(verbose_name=_('provider'), max_length=30, choices=provider_choices)
    uid = models.CharField(verbose_name=_('uid'), max_length=settings.UID_MAX_LENGTH)
    last_login = models.DateTimeField(verbose_name=_('last login'), auto_now=True)
    date_joined = models.DateTimeField(verbose_name=_('date joined'), auto_now_add=True)
    extra_data = JSONField(verbose_name=_('extra data'), default=dict)

    class Meta:
        unique_together = ('provider', 'uid')
        verbose_name = _('social account')
        verbose_name_plural = _('social accounts')

    def authenticate(self):
        return authenticate(account=self)

    def __str__(self):
        return force_text(self.user)

    def get_profile_url(self):
        return self.get_provider_account().get_profile_url()

    def get_avatar_url(self):
        return self.get_provider_account().get_avatar_url()

    def get_provider(self):
        return providers.registry.by_id(self.provider)

    def get_provider_account(self):
        return self.get_provider().wrap_account(self)


class SocialToken(models.Model):
    account = models.ForeignKey(SocialAccount, on_delete=models.CASCADE)
    token = models.TextField(verbose_name=_('token'), help_text=_('"oauth_token" (OAuth1) or access token (OAuth2)'))
    token_secret = models.TextField(blank=True, verbose_name=_('token secret'), help_text=_('"oauth_token_secret" (OAuth1) or refresh token (OAuth2)'))
    expires_at = models.DateTimeField(blank=True, null=True, verbose_name=_('expires at'))

    class Meta:
        verbose_name = _('social application token')
        verbose_name_plural = _('social application tokens')

    def __str__(self):
        return self.token
