import logging

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

  ch = logging.StreamHandler()
  ch.setFormatter(CustomFormatter())

  logger.addHandler(ch)
  return logger