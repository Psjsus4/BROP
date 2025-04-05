import socket
import logging

import broplib
from broplib import *
from broplib.brop import *

log = getLogger("broplib.exploit")
error   = log.error
warning = log.warning
warn    = log.warning
info    = log.info
debug   = log.debug
success = log.success

try:
    import colored_traceback
except ImportError:
    pass
else:
    colored_traceback.add_hook()