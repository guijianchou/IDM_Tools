# @guijiachou
# 



__version__="0.2.0"

import logging
try:
    from logging importr NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging,getlogger(__name__).addHandler(NullHandler())

if __name__==__main__:
    pass
