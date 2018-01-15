# -*- coding: utf-8 -*-
import pkg_resources

try:
    __version__ = pkg_resources.get_distribution(__name__).version
except:
    __version__ = 'unknown'


# public API
from YahooSports.yahoo_sports import YahooConnection
from YahooSports.exceptions import OAuthExpired, OAuth401Error, NoRefreshToken
