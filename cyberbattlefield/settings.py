"""
Cyber Battlefield - Django Settings
=====================================
Dual Autonomous AI for Software Vulnerability Exploitation and Defense
"""

import os
from pathlib import Path

import environ

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
env = environ.Env(
    DJANGO_DEBUG=(bool, True),
    DJANGO_ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1", "0.0.0.0"]),
    DB_NAME=(str, "cyberbattlefield"),
    DB_USER=(str, "cyber_admin"),
    DB_PASSWORD=(str, "cyber_password_123"),
    DB_HOST=(str, "localhost"),
    DB_PORT=(int, 5432),
    REDIS_URL=(str, "redis://localhost:6379/0"),
    CELERY_BROKER_URL=(str, "redis://localhost:6379/1"),
    OLLAMA_BASE_URL=(str, "http://localhost:11434"),
    OLLAMA_MODEL=(str, "llama3.1:8b"),
    LLM_TIMEOUT=(int, 120),
    LLM_MAX_RETRIES=(int, 3),
    ALLOWED_TARGET_CIDRS=(list, ["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]),
    MAX_ACTIONS_PER_ROUND=(int, 50),
    SIMULATION_MAX_ROUNDS=(int, 100),
    LOG_LEVEL=(str, "INFO"),
    LOG_FILE=(str, "logs/cyberbattlefield.log"),
)

env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

# ─── Security ───────────────────────────────────────────────────────
SECRET_KEY = env("DJANGO_SECRET_KEY", default="dev-secret-key-not-for-production")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS")

# ─── Application Definition ────────────────────────────────────────
INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third party
    "django_extensions",
    "corsheaders",
    "rest_framework",
    "channels",
    # Project apps
    "core.apps.CoreConfig",
    "red_team.apps.RedTeamConfig",
    "blue_team.apps.BlueTeamConfig",
    "simulation.apps.SimulationConfig",
    "dashboard.apps.DashboardConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cyberbattlefield.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "cyberbattlefield.wsgi.application"
ASGI_APPLICATION = "cyberbattlefield.asgi.application"

# ─── Database ───────────────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    },
    "postgres": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("DB_NAME"),
        "USER": env("DB_USER"),
        "PASSWORD": env("DB_PASSWORD"),
        "HOST": env("DB_HOST"),
        "PORT": env("DB_PORT"),
    },
}

# ─── Cache (Redis) ──────────────────────────────────────────────────
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
}

# ─── Channel Layers ────────────────────────────────────────────────
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    },
}

# ─── Celery ─────────────────────────────────────────────────────────
CELERY_BROKER_URL = env("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = env("REDIS_URL")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"

# ─── REST Framework ────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

# ─── Auth ───────────────────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ─── Internationalization ──────────────────────────────────────────
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ─── Static Files ──────────────────────────────────────────────────
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

# ─── Default Primary Key ───────────────────────────────────────────
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ─── LLM Configuration ─────────────────────────────────────────────
OLLAMA_BASE_URL = env("OLLAMA_BASE_URL")
OLLAMA_MODEL = env("OLLAMA_MODEL")
LLM_TIMEOUT = env("LLM_TIMEOUT")
LLM_MAX_RETRIES = env("LLM_MAX_RETRIES")

# ─── Safety Configuration ──────────────────────────────────────────
ALLOWED_TARGET_CIDRS = env("ALLOWED_TARGET_CIDRS")
MAX_ACTIONS_PER_ROUND = env("MAX_ACTIONS_PER_ROUND")
SIMULATION_MAX_ROUNDS = env("SIMULATION_MAX_ROUNDS")

# ─── Logging ────────────────────────────────────────────────────────
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {module}.{funcName}:{lineno} - {message}",
            "style": "{",
        },
        "simple": {
            "format": "[{asctime}] {levelname} - {message}",
            "style": "{",
        },
        "json": {
            "()": "core.logger.JsonFormatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
            "level": "DEBUG",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "cyberbattlefield.log"),
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 5,
            "formatter": "json",
            "level": "DEBUG",
        },
        "red_team_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "red_team.log"),
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "json",
            "level": "DEBUG",
        },
        "blue_team_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "blue_team.log"),
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "json",
            "level": "DEBUG",
        },
        "simulation_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "simulation.log"),
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "json",
            "level": "DEBUG",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "WARNING",
            "propagate": True,
        },
        "core": {
            "handlers": ["console", "file"],
            "level": env("LOG_LEVEL"),
            "propagate": False,
        },
        "red_team": {
            "handlers": ["console", "red_team_file"],
            "level": env("LOG_LEVEL"),
            "propagate": False,
        },
        "blue_team": {
            "handlers": ["console", "blue_team_file"],
            "level": env("LOG_LEVEL"),
            "propagate": False,
        },
        "simulation": {
            "handlers": ["console", "simulation_file"],
            "level": env("LOG_LEVEL"),
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": env("LOG_LEVEL"),
    },
}

# ─── CORS ───────────────────────────────────────────────────────────
CORS_ALLOW_ALL_ORIGINS = DEBUG
