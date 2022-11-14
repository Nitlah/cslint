import logging
from Config.config import LOG_PATH
logging.basicConfig(
    level=logging.INFO,
    filename=LOG_PATH,
    datefmt='%Y/%m/%d %H:%M:%S',
    format='%(asctime)s - %(levelname)s - %(process)d - %(module)s - %(funcName)s - %(lineno)d : %(message)s'
)
logger = logging.getLogger(__name__)
