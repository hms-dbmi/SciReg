"""
Django settings for SciReg project.

Generated by 'django-admin startproject' using Django 1.10.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.10/ref/settings/
"""

import os
import base64

from os.path import normpath, join, dirname, abspath
from django.utils.crypto import get_random_string
from django.contrib.messages import constants as message_constants
from pythonpstore.pythonpstore import SecretStore
import sys

chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY", get_random_string(50, chars))
EMAIL_CONFIRM_SALT = os.environ.get("SALT", get_random_string(50, chars))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

secret_store = SecretStore()
PARAMETER_PATH = os.environ.get("PS_PATH", None)

if PARAMETER_PATH:
    ALLOWED_HOSTS = [secret_store.get_secret_for_key(PARAMETER_PATH + '.allowed_hosts')]
else:
    ALLOWED_HOSTS = ["localhost"]

# Set the message level.
MESSAGE_LEVEL = message_constants.INFO

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'bootstrap3',
    'registration',
    'rest_framework',
    'pyauth0jwt',
    'pyauth0jwtrest'
]

MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware'
]

ROOT_URLCONF = 'SciReg.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [normpath(join(BASE_DIR, 'templates'))],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'SciReg.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'scireg',
        'USER': os.environ.get("MYSQL_USERNAME"),
        'PASSWORD': os.environ.get("MYSQL_PASSWORD"),
        'HOST': os.environ.get("MYSQL_HOST"),
        'PORT': os.environ.get("MYSQL_PORT"),
    }
}

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


#########
# STATIC FILE CONFIGS
DJANGO_ROOT = dirname(dirname(abspath(__file__)))
STATIC_ROOT = normpath(join(DJANGO_ROOT, 'assets'))
STATIC_URL = '/static/'
STATICFILES_DIRS = (
    normpath(join(DJANGO_ROOT, 'static')),
)
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)
#########

#########
# Specifics
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAuthenticated',
                                   'rest_framework.permissions.DjangoModelPermissions'),
    'PAGE_SIZE': 10,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'pyauth0jwtrest.auth0authenticaterest.Auth0JSONWebTokenAuthentication',
    ),
}

JWT_AUTH = {
    'JWT_SECRET_KEY': base64.b64decode(os.environ.get("AUTH0_SECRET", ""), '-_'),
    'JWT_AUDIENCE': os.environ.get("AUTH0_CLIENT_ID"),
    'JWT_PAYLOAD_GET_USERNAME_HANDLER': 'registration.permissions.jwt_get_username_from_payload'
}

AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_SECRET = os.environ.get("AUTH0_SECRET")
AUTH0_SUCCESS_URL = os.environ.get("AUTH0_SUCCESS_URL")
AUTH0_LOGOUT_URL = os.environ.get("AUTH0_LOGOUT_URL")

LOGIN_URL = '/login/'

AUTHENTICATION_LOGIN_URL = os.environ.get("AUTHENTICATION_LOGIN_URL")

AUTHENTICATION_BACKENDS = ('pyauth0jwt.auth0authenticate.Auth0Authentication', 'django.contrib.auth.backends.ModelBackend')

COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN")

EMAIL_BACKEND = 'django_smtp_ssl.SSLEmailBackend'
EMAIL_USE_SSL = True
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
EMAIL_PORT = os.environ.get("EMAIL_PORT")

CONFIRM_EMAIL_URL = os.environ.get("CONFIRM_EMAIL_URL")
DEFAULT_FROM_EMAIL = "ppm-no-reply@dbmi.hms.harvard.edu"

LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
        },
        'file_debug': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
        },
        'file_error': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': 'error.log',
        }
    },
    'root': {
        'handlers': ['console', 'file_debug'],
        'level': 'DEBUG'
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file_error'],
            'level': 'ERROR',
            'propagate': True,
        },
    },
}

# Default settings
BOOTSTRAP3 = {

    # The URL to the jQuery JavaScript file
    'jquery_url': '//code.jquery.com/jquery.min.js',

    # The Bootstrap base URL
    'base_url': '//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/',

    # The complete URL to the Bootstrap CSS file (None means derive it from base_url)
    'css_url': None,

    # The complete URL to the Bootstrap JavaScript file (None means derive it from base_url)
    'javascript_url': None,

    # Include jQuery with Bootstrap JavaScript (affects django-bootstrap3 template tags)
    'include_jquery': True,
}

#########

try:
    from .local_settings import *
except ImportError:
    pass
