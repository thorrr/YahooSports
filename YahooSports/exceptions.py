from __future__ import (absolute_import, division, print_function, unicode_literals)
from builtins import *

class OAuthExpired(Exception):
    pass


class OAuth401Error(Exception):
    pass


class NoRefreshToken(Exception):
    pass
