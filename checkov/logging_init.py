import logging
import os
from io import StringIO

from checkov.common.resource_code_logger_filter import add_resource_code_filter_to_logger

LOG_LEVEL = os.getenv('LOG_LEVEL', 'WARNING').upper()
logging.basicConfig(level=LOG_LEVEL)
log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
root_logger = logging.getLogger()
add_resource_code_filter_to_logger(root_logger)
stream_handler = root_logger.handlers[0]
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(LOG_LEVEL)
root_logger.setLevel(LOG_LEVEL)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
logging.getLogger("urllib3.connectionpool").propagate = False
logging.getLogger("urllib3").propagate = False
log_stream = StringIO()
capture_handler = logging.StreamHandler(stream=log_stream)
capture_handler.setFormatter(log_formatter)
capture_handler.setLevel(LOG_LEVEL)
root_logger.addHandler(capture_handler)


def enable_log_capture() -> None:
    """Start buffering debug logs into log_stream, for --support to upload.

    Only --support reads the stream, so this stays off until it is known to be set: building,
    formatting and buffering records nobody reads costs more than the scan itself on large repos.
    """
    root_logger.setLevel(logging.DEBUG)
    capture_handler.setLevel(logging.DEBUG)
