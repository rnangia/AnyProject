# -*- coding: utf-8 -*-
"""
Django settings for PROJECTNAME project.
For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/
For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""
from __future__ import absolute_import, unicode_literals
import datetime
import environ
import os
import sys

from .shop import *

ROOT_DIR = environ.Path(__file__) - 3
APPS_DIR = ROOT_DIR.path('PROJECTNAMESMALL')

env = environ.Env()
env.read_env(ROOT_DIR('.env'))

# APP CONFIGURATION
# ------------------------------------------------------------------------------
DJANGO_APPS = (
    # Admin
    'django.contrib.admin',
    # Default Django apps:
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
)

THIRD_PARTY_APPS = (
    'rest_framework',
#     'rest_framework.authtoken',
    'treebeard',
    'graphene_django', #graphql
    'corsheaders', #cors
)

# Apps specific for this project go here.
LOCAL_APPS = (
    'PROJECTNAMESMALL.users',
#    'PROJECTNAMESMALL.core',
#    'PROJECTNAMESMALL.address',
#    'PROJECTNAMESMALL.shipping',
#    'PROJECTNAMESMALL.partner',
#    'PROJECTNAMESMALL.catalogue',
#    'PROJECTNAMESMALL.offer',
#    'PROJECTNAMESMALL.basket',
#    'PROJECTNAMESMALL.customer',
#    'PROJECTNAMESMALL.promotions',
#    'PROJECTNAMESMALL.order',
#    'PROJECTNAMESMALL.checkout',
#    'PROJECTNAMESMALL.payment',
#    'PROJECTNAMESMALL.wishlists',
#    'PROJECTNAMESMALL.search',
)

# See: https://docs.djangoproject.com/en/dev/ref/settings/#installed-apps
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# MIDDLEWARE CONFIGURATION
# ------------------------------------------------------------------------------
MIDDLEWARE = (
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

# DEBUG
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#debug
DEBUG = env.bool('DJANGO_DEBUG', False)

# EMAIL CONFIGURATION
# ------------------------------------------------------------------------------
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# MANAGER CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#admins
ADMINS = (
    ("""Full Name""", 'emailaddress@gmail.com'),
)

# See: https://docs.djangoproject.com/en/dev/ref/settings/#managers
MANAGERS = ADMINS

# DATABASE CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#databases
DATABASES = {
    'default': env.db('DATABASE_URL', default='postgres://database'),
}
DATABASES['default']['ATOMIC_REQUESTS'] = True

# GENERAL CONFIGURATION
# ------------------------------------------------------------------------------
# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'UTC'

# See: https://docs.djangoproject.com/en/dev/ref/settings/#language-code
LANGUAGE_CODE = 'en-us'

# See: https://docs.djangoproject.com/en/dev/ref/settings/#site-id
SITE_ID = 1

# See: https://docs.djangoproject.com/en/dev/ref/settings/#use-i18n
USE_I18N = True

# See: https://docs.djangoproject.com/en/dev/ref/settings/#use-l10n
USE_L10N = True

# See: https://docs.djangoproject.com/en/dev/ref/settings/#use-tz
USE_TZ = True

# TEMPLATE CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#templates
TEMPLATES = [
    {
        # See: https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-TEMPLATES-BACKEND
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # See: https://docs.djangoproject.com/en/dev/ref/settings/#template-dirs
        'DIRS': [
            str(APPS_DIR.path('templates'))
        ],
        'OPTIONS': {
            # See: https://docs.djangoproject.com/en/dev/ref/settings/#template-debug
            'debug': DEBUG,
            # See: https://docs.djangoproject.com/en/dev/ref/settings/#template-loaders
            # https://docs.djangoproject.com/en/dev/ref/templates/api/#loader-types
            'loaders': [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
            ],
            # See: https://docs.djangoproject.com/en/dev/ref/settings/#template-context-processors
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# STATIC FILE CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/#std:setting-STATICFILES_DIRS
STATICFILES_DIRS = (os.path.join(str(APPS_DIR),"assets","staticfiles"),)

# See: https://docs.djangoproject.com/en/dev/ref/settings/#static-root
STATIC_ROOT = os.path.join(str(APPS_DIR),"assets","static")

# See: https://docs.djangoproject.com/en/dev/ref/settings/#static-url
STATIC_URL = '/static/'



# See: https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/#staticfiles-finders
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

# MEDIA CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#media-root
MEDIA_ROOT = os.path.join(str(APPS_DIR),"media")

# See: https://docs.djangoproject.com/en/dev/ref/settings/#media-url
MEDIA_URL = '/media/'

# URL Configuration
# ------------------------------------------------------------------------------
ROOT_URLCONF = 'config.urls'

# See: https://docs.djangoproject.com/en/dev/ref/settings/#wsgi-application
WSGI_APPLICATION = 'config.wsgi.application'

# REST FRAMEWORK
# ------------------------------------------------------------------------------

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_PARSER_CLASSES': (
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ),
}

# GRAPHQL
# -------------------------------------------------------------

GRAPHENE = {
    'SCHEMA': 'config.schema.schema',
    'MIDDLEWARE': (
        'graphene_django.debug.DjangoDebugMiddleware',
    )
}

# PASSWORD VALIDATION
# https://docs.djangoproject.com/en/dev/ref/settings/#auth-password-validators
# ------------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# AUTHENTICATION CONFIGURATION
# ------------------------------------------------------------------------------
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)

# allauth settings for email based authentication
AUTH_USER_MODEL = 'users.User'
PASSWORD_MIN_LENGTH= 8
EMAIL_MAX_LENGTH = 254
EMAIL_REQUIRED = True
EMAIL_VERIFICATION = 'MANDATORY'
UNIQUE_EMAIL = True
DEFAULT_FROM_EMAIL = 'mail.websitename.com'
EMAIL_CONFIRMATION_COOLDOWN = 3 * 60
EMAIL_CONFIRMATION_EXPIRE_DAYS = 3
EMAIL_SUBJECT_PREFIX = None
DEFAULT_HTTP_PROTOCOL = "http"
STORE_TOKENS = True
UID_MAX_LENGTH = 191
SALT = 'account'
ACCOUNT_AUTHENTICATION_METHOD = 'USERNAME'
ACCOUNT_EMAIL_REQUIRED = False
LOGIN_REDIRECT_URL = '/'


OLD_PASSWORD_FIELD_ENABLED = True
LOGOUT_ON_PASSWORD_CHANGE = True


# csrf in header
CSRF_COOKIE_NAME = 'xsrf-token'
CSRF_COOKIE_DOMAIN = 'websitename.com'
CSRF_TRUSTED_ORIGINS = ['api.websitename.com', 'www.websitename.com']

# CORS
CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_WHITELIST = (
    'https://www.websitename.com'
)

# LOGIN_REDIRECT_URL = 'users:redirect'
LOGIN_URL = 'account_login'

# Google recaptcha settings

RECAPTCHA_SECRET_KEY = 'RECAPTCHA_SECRET_KEY'

PAGE_CACHE_SECONDS = 1

# Google Identity settings

GOOGLE_IDENTITY_CLIENT_ID = "GOOGLE_IDENTITY_CLIENT_ID"
GOOGLE_IDENTITY_SECRET = "GOOGLE_IDENTITY_SECRET"

# Paypal settings

PAYPAL_CLIENT_ID = "PAYPAL_CLIENT_ID"
PAYPAL_CLIENT_SECRET = "PAYPAL_CLIENT_SECRET"

# Mailgun settings

MAILGUN_SECRET_KEY = "MAILGUN_SECRET_KEY"

# Shop settings
# --------------------------------------------------------------
DEFAULT_CURRENCY = 'AUD'
SLUG_ALLOW_UNICODE = False
SLUG_MAP = {}
SLUG_BLACKLIST = []
IMAGE_FOLDER = 'images/products/%Y/%m/'
PROMOTION_FOLDER = 'images/promotions'
MAX_BASKET_QUANTITY_THRESHOLD = 50000

# Logging

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[django] %(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
