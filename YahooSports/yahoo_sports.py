from __future__ import (absolute_import, division, print_function, unicode_literals)
from builtins import *
import logging
logger = logging.getLogger(__name__)
import json
from os.path import isfile
import re
import pickle
import tempfile
import xml.etree.ElementTree as ET
import xml.dom.minidom
import functools

from rauth import OAuth2Service, OAuth2Session
from requests.exceptions import ConnectionError

from YahooSports.exceptions import OAuthExpired, OAuth401Error, NoRefreshToken


class YahooResponse(object):
    def __init__(self, response):
        self.response = response

    @property
    def clean_text(self):
        root_obj = ET.fromstring(self.response.text.encode("utf-8"))
        #get rid of namespaces to make searching easier
        for elem in root_obj.getiterator():
            if not hasattr(elem.tag, 'find'):
                continue
            i = elem.tag.find('}')
            if i >= 0:
                elem.tag = elem.tag[i + 1:]
        #convert back to xml string
        xml_string = ET.tostring(root_obj)
        return _pretty_xml(xml_string)

    def __getattr__(self, attr):
        return getattr(self.response, attr)


def _read_auth_keys(filename):
    # return dictionary from auth_keys.txt - simple colon delimited format
    prog = re.compile("^(.+?): *(.*)")
    rv = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.rstrip()
            if len(line) > 0:
                k, v = prog.search(line).groups()
                rv[k] = v
    return rv


def _pretty_xml(xml_string):
    _xml = xml.dom.minidom.parseString(xml_string)
    return _xml.toprettyxml(indent="  ", newl="")


def _yahoo_oauth_response_decoder(json_struct, refresh_token_recipient):
    """default rauth implementation needs a custom decoder for Yahoo's auth session.

    Args:
        refresh_token_recipient: an empty dict.  refresh token will be stored in key 'refresh_token'
    """
    rv = json.loads(json_struct)
    refresh_token_recipient['refresh_token'] = rv['refresh_token']
    return rv


class SerializableSession(object):
    """This is an object with a single method:  'get', which forwards it on to self.session.

    Used instead of the raw OAuth2Session object since this has an additional property
    'refresh_token'.
    """
    def __init__(self, session):
        assert isinstance(session, OAuth2Session)
        self.session = session
        self._refresh_token = None

    @property
    def refresh_token(self):
        return self._refresh_token

    @refresh_token.setter
    def refresh_token(self, value):
        self._refresh_token = value

    def __getattr__(self, attr):
        if attr in ["delete", "get", "head", "options", "patch", "post", "put"]:
            return getattr(self.session, attr)
        raise AttributeError


class YahooOAuth2Urls(object):
    url_get_token = 'https://api.login.yahoo.com/oauth2/get_token'
    url_request_auth = 'https://api.login.yahoo.com/oauth2/request_auth'


class YahooConnection(object):
    url_base = "https://fantasysports.yahooapis.com/fantasy/v2/"

    def __init__(
            self, auth_filename=None, OAUTH_SHARED_SECRET=None, OAUTH_CONSUMER_KEY=None,
            session_object=None):
        """Use consumer key and shared secret to get an oauth session.  Ask user for PIN if the
        session is not stored in auth_filename or auth_filename is None

        Args:
            session_object: a previously initialized session object of type SerializableSession.
                            Accessible from self.session.  These are pickleable and you can save
                            them along with your shared secret and consumer key.

        """
        self.auth_filename = auth_filename
        self.session = None
        self.yahoo_oauth_service = None
        self.request_token = None
        self.request_token_secret = None

        if not auth_filename:
            if not (OAUTH_CONSUMER_KEY and OAUTH_SHARED_SECRET):
                raise ValueError("Must specify both OAUTH_CONSUMER_KEY and OAUTH_SHARED_SECRET")
            self.consumer_secret = OAUTH_SHARED_SECRET
            self.consumer_key = OAUTH_CONSUMER_KEY
        else:
            if OAUTH_CONSUMER_KEY is not None or OAUTH_SHARED_SECRET is not None:
                raise ValueError("Must specify either authFile or "
                                 "both OAUTH_CONSUMER_KEY and OAUTH_SHARED_SECRET")

        auth_session_file = None
        if auth_filename:
            auth_keys = _read_auth_keys(auth_filename)
            self.consumer_secret = auth_keys['consumer_secret']
            self.consumer_key = auth_keys['consumer_key']
            auth_session_file = auth_keys.get('auth_session_file')

        if auth_session_file and isfile(auth_session_file):
            if session_object is not None:
                raise ValueError(
                    "Can't pass in session_object if auth_session_file exists in {}".format(
                        auth_filename))
            # load session object from location specified in auth_filename
            with open(auth_session_file, 'rb') as pickle_file:
                self.session = pickle.load(pickle_file)
        else:
            self.session = session_object

        self.yahoo_oauth_service = self.oauth_2_service()  # pylint: disable=R0204

    def oauth_2_service(self):
        service = OAuth2Service(
            name="yahoo",
            client_id=self.consumer_key,
            client_secret=self.consumer_secret,
            base_url=self.url_base,
            authorize_url=YahooOAuth2Urls.url_request_auth,
            access_token_url=YahooOAuth2Urls.url_get_token)
        return service

    def auth_url(self):
        """reset self.session and return the auth URL that should be given to enter_pin()"""
        params = {'redirect_uri': 'oob', 'response_type': 'code'}
        auth_url = self.yahoo_oauth_service.get_authorize_url(**params)
        return auth_url

    def enter_pin(self, pin):
        """enter pin to get a new valid session.  save the session if we've specified an
        auth_filename"""
        data = {'code': "{}".format(pin), 'grant_type': 'authorization_code',
                'redirect_uri': 'oob'}
        refresh_token_holder = {}
        self.session = SerializableSession(
            self.yahoo_oauth_service.get_auth_session(
                data=data,
                decoder=lambda x: _yahoo_oauth_response_decoder(x, refresh_token_holder)))
        self.session.refresh_token = refresh_token_holder['refresh_token']
        self.save_session()

    def refresh_session(self):
        """Refresh session using the long-lived 'refresh_token' from Yahoo."""
        if not hasattr(self.session, 'refresh_token'):
            raise NoRefreshToken()

        logger.info("session expired.  refreshing.")

        refresh_data = {'refresh_token': "{}".format(self.session.refresh_token),
                        'grant_type': 'refresh_token',
                        'redirect_uri': 'oob'}
        refresh_token_holder = {}
        self.session = SerializableSession(
            self.yahoo_oauth_service.get_auth_session(
                data=refresh_data,
                decoder=lambda x: _yahoo_oauth_response_decoder(x, refresh_token_holder)))
        self.session.refresh_token = refresh_token_holder['refresh_token']
        self.save_session()

    def save_session(self):
        assert self.session

        if not self.auth_filename:
            return

        pickle_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
        pickle_file_name = pickle_file.name
        pickle.dump(self.session, pickle_file)
        pickle_file.close()

        with open(self.auth_filename, 'w') as f:
            f.write("consumer_secret: {}\n".format(self.consumer_secret))
            f.write("consumer_key: {}\n".format(self.consumer_key))
            f.write("auth_session_file: {}\n".format(pickle_file_name))

    def is_live_session(self):
        if not self.session:
            return False
        try:
            response = self.session.get(self.url_base + "game/223")
        except ConnectionError:
            return False
        return response.ok

    def request(self, location, data=None,
                method="get", headers=None,
                refresh_token=False, *args, **kwargs):

        def do_request():
            return getattr(self.session, method)(
                self.url_base + location,
                data=data,
                headers=headers,
                *args,
                **kwargs
            )

        def check_response(res):
            if not res.ok:
                out = re.search(r'oauth_problem="([^"]+)', res.text)
                oauth_problem_code = None
                if out:
                    oauth_problem_code = out.groups()[0]
                if res.status_code == 401:
                    if oauth_problem_code == "token_expired":
                            raise OAuthExpired
                    else:
                        raise OAuth401Error(oauth_problem_code)
                res.raise_for_status()
            else:
                return res
        try:
            res = do_request()
            return YahooResponse(check_response(res))
        except OAuthExpired:
            if refresh_token:
                self.refresh_session()
                res = do_request()
                return YahooResponse(check_response(res))

    def __getattr__(self, attr):
        if attr in ["delete", "get", "head", "options", "patch", "post", "put"]:
            return functools.partial(self.request, method=attr)
        raise AttributeError
