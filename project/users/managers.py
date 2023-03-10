from datetime import timedelta

from django.db import models
from django.db.models import Q
from django.utils import timezone


class EmailAddressManager(models.Manager):

    def add_email(self, request, user, email, confirm=False, signup=False):
        email_address, created = self.get_or_create(user=user, email__iexact=email, defaults={"email": email})

        if created and confirm:
            email_address.send_confirmation(request, signup=signup)

        return email_address

    def get_primary(self, user):
        try:
            return self.get(user=user, primary=True)
        except self.model.DoesNotExist:
            return None

    def get_users_for(self, email):
        # this is a list rather than a generator because we probably want to
        # do a len() on it right away
        return [address.user for address in self.filter(verified=True, email__iexact=email)]

    def fill_cache_for_user(self, user, addresses):
        """
        In a multi-db setup, inserting records and re-reading them later
        on may result in not being able to find newly inserted
        records. Therefore, we maintain a cache for the user so that
        we can avoid database access when we need to re-read..
        """
        user._emailaddress_cache = addresses

    def get_for_user(self, user, email):
        cache_key = '_emailaddress_cache'
        addresses = getattr(user, cache_key, None)
        if addresses is None:
            ret = self.get(user=user, email__iexact=email)
            # To avoid additional lookups when e.g.
            # EmailAddress.set_as_primary() starts touching self.user
            ret.user = user
            return ret
        else:
            for address in addresses:
                if address.email.lower() == email.lower():
                    return address
            raise self.model.DoesNotExist()


class SocialAppManager(models.Manager):
    def get_current(self, provider, request=None):
        cache = {}
        if request:
            cache = getattr(request, '_socialapp_cache', {})
            request._socialapp_cache = cache
        app = cache.get(provider)
        if not app:
            site = get_current_site(request)
            app = self.get(
                sites__id=site.id,
                provider=provider)
            cache[provider] = app
        return app
