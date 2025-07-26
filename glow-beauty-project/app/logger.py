# app/logger.py

import os
import logging
import logging.config

# Ensure logs/ directory exists
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "detailed": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s] [%(filename)s:%(lineno)d] - %(message)s"
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "detailed"
        },
        "auth_file": {
            "class": "logging.FileHandler",
            "formatter": "detailed",
            "filename": os.path.join(LOG_DIR, "auth.log"),
            "mode": "a"
        },
        "core_file": {
            "class": "logging.FileHandler",
            "formatter": "detailed",
            "filename": os.path.join(LOG_DIR, "core.log"),
            "mode": "a"
        }
    },

    "loggers": {
        "auth": {
            "handlers": ["console", "auth_file"],
            "level": "DEBUG",
            "propagate": False
        },
        "core": {
            "handlers": ["console", "core_file"],
            "level": "DEBUG",
            "propagate": False
        }
    }
}

_initialized = False

def get_logger(name: str):
    global _initialized
    if not _initialized:
        logging.config.dictConfig(LOGGING_CONFIG)
        _initialized = True
    return logging.getLogger(name)
