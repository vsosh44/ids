from logging.handlers import RotatingFileHandler
import logging

logger = logging.getLogger("network_ids")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    "/var/log/network_ids/network_ids.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8"
)

formatter = logging.Formatter(
    "%(asctime)s: %(message)s"
)
handler.setFormatter(formatter)

logger.addHandler(handler)
