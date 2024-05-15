import logging
import os

class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    green = "\x1b[32;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: green + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def get_logger(name, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())

    # General log file handler
    general_log_path = './logs/info.log'
    os.makedirs(os.path.dirname(general_log_path), exist_ok=True)
    with open(general_log_path, 'w'):  # Clear the log file
        pass
    fh = logging.FileHandler(general_log_path)
    fh.setLevel(logging.DEBUG)
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)')
    fh.setFormatter(file_format)

    # Error log file handler
    error_log_path = './logs/error.log'
    os.makedirs(os.path.dirname(error_log_path), exist_ok=True)
    with open(error_log_path, 'w'):  # Clear the log file
        pass
    efh = logging.FileHandler(error_log_path)
    efh.setLevel(logging.ERROR)
    efh.setFormatter(file_format)

    # Add handlers to the logger
    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.addHandler(efh)

    return logger
