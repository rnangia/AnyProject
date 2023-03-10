from django.contrib.auth.signals import user_logged_out  # noqa
from django.dispatch import Signal


user_logged_in = Signal(providing_args=["request", "user"])

# Typically followed by `user_logged_in` (unless, e-mail verification kicks in)
user_signed_up = Signal(providing_args=["request", "user"])

password_set = Signal(providing_args=["request", "user"])
password_changed = Signal(providing_args=["request", "user"])
password_reset = Signal(providing_args=["request", "user"])

email_confirmed = Signal(providing_args=["request", "email_address"])
email_confirmation_sent = Signal(providing_args=["request", "confirmation", "signup"])

email_added = Signal(providing_args=["request", "user", "email_address"])
email_removed = Signal(providing_args=["request", "user", "email_address"])


"""
    Sent after a user successfully authenticates via a social provider,
    but before the login is actually processed. This signal is emitted
    for social logins, signups and when connecting additional social
    accounts to an account.
"""
pre_social_login = Signal(providing_args=["request", "sociallogin"])

# Sent after a user connects a social account to a their local account.
social_account_added = Signal(providing_args=["request", "sociallogin"])

"""
    Sent after a user connects an already existing social account to a
    their local account. The social account will have an updated token and
    refreshed extra_data.
"""
social_account_updated = Signal(providing_args=["request", "sociallogin"])

# Sent after a user disconnects a social account from their local account.
social_account_removed = Signal(providing_args=["request", "socialaccount"])
