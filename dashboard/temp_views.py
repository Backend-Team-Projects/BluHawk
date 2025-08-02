from datetime import timedelta
from BluHawk import load_env as myenv
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = myenv.SECRET_KEY

DEBUG = False

STATIC_ROOT = BASE_DIR / "staticfiles"


ALLOWED_HOSTS = ["*"]


INSTALLED_APPS = [
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt.token_blacklist',
    'session_management',
    'rest_framework.authtoken',
    'corsheaders',
    'BluHawk',
    'dashboard',
    'django_celery_beat',
    'user_settings',
    'usage',
    'clatscope',
    
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'BluHawk.middlewares.UserRequestTrackingMiddleware',
]

ROOT_URLCONF = 'BluHawk.urls'

CORS_ALLOW_ALL_ORIGINS = True


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
           BASE_DIR / 'templates'
        ],
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


WSGI_APPLICATION = 'BluHawk.wsgi.application'


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'bluhawkdb',
        'USER': 'admin',
        'PASSWORD': myenv.POSTGRESQL_PASSWORD,
        'HOST': 'localhost',
        'PORT': '5432',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

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


SIMPLE_JWT = {
    'BLACKLIST_AFTER_ROTATION': True,
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=10),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
}


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}


LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'

# custom env

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = myenv.EMAIL_HOST_USER
EMAIL_HOST_PASSWORD = myenv.EMAIL_HOST_PASSWORD

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'


from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    
    'cisa_vulnerabilities_refresh': {
        'task': 'dashboard.tasks.cisa_vulnerabilities_refresh',
        'schedule': crontab(minute='*/5'),
        'args': (),
    },
    'refreshMitreData': {
        'task': 'dashboard.tasks.refreshMitreData',
        'schedule': crontab(minute='*/5'),
        'args': (),
    },
}

import os
from django.conf import settings

JAZZMIN_SETTINGS = {
    "site_title": "BluHawk Admin",
    "site_header": "BluHawk Threat Console",
    "site_brand": "BluHawk",
    "welcome_sign": "Welcome to BluHawk Admin Panel",
    "copyright": "BluHawk",
    "show_sidebar": True,
    "navigation_expanded": True,
    "hide_apps": [],
    "icons": {
        "auth": "fas fa-users-cog",
        "yourapp.ThreatIntel": "fas fa-bug",
    },
    "changeform_format": "collapsible",  # or "horizontal_tabs", "vertical_tabs"
    "show_ui_builder": False,
}

JAZZMIN_UI_TWEAKS = {
    "theme": "darkly",  # Bootstrap themes like cerulean, flatly, darkly, etc.
    "custom_css": "css/admin_custom.css",
}

CSRF_TRUSTED_ORIGINS = [
    "https://bluhawkapi.twilightparadox.com",
]


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'celery_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(settings.BASE_DIR, 'celery.log'),
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'celery': {
            'handlers': ['celery_file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'celery.worker': {
            'handlers': ['celery_file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'celery.beat': {
            'handlers': ['celery_file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'celery.task': {
            'handlers': ['celery_file', 'console'],
            'level': 'ERROR',
            'propagate': True,
        },
    },
}