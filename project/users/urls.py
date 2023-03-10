from django.conf.urls import url
from .views import (
    LoginView, LogoutView, UserDetailsView, PasswordChangeView,
    PasswordResetView, PasswordResetConfirmView, RegisterView, VerifyEmailView,
    GoogleLogin, TokenView
)

app_name = "users"

urlpatterns = [
    # URLs that do not require a session or valid token
    url(r'^register/$', RegisterView.as_view(), name='rest_register'),
    url(r'^verify-email/(?P<key>[-:\w]+)/$', VerifyEmailView.as_view(), name='rest_verify_email'),
    url(r'^login/$', LoginView.as_view(), name='rest_login'),
    url(r'^password/reset/$', PasswordResetView.as_view(), name='rest_password_reset'),
    url(r'^password/reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', PasswordResetConfirmView.as_view(), name='rest_password_reset_confirm'),
    url(r'^google/$', GoogleLogin.as_view(), name='google_login'),
    # URLs that require a user to be logged in with a valid session / token.
    url(r'^2kn/$', TokenView.as_view(), name='token_login'),
    url(r'^user/$', UserDetailsView.as_view(), name='rest_user_details'),
    url(r'^password/change/$', PasswordChangeView.as_view(), name='rest_password_change'),
    url(r'^logout/$', LogoutView.as_view(), name='rest_logout'),
]
