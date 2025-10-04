import logging
from logging.handlers import RotatingFileHandler

LOGFILE = "apkghost.log"

logger = logging.getLogger("apkghost")
logger.setLevel(logging.DEBUG)

fh = RotatingFileHandler(LOGFILE, maxBytes=2*1024*1024, backupCount=2)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
fh.setFormatter(fmt)
logger.addHandler(fh)

# Console handler
ch = logging.StreamHandler()
ch.setFormatter(fmt)
logger.addHandler(ch)
