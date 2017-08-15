from __future__ import (absolute_import, division, print_function, unicode_literals)
from builtins import *

import json
from os.path import isfile
import re
import pickle
import tempfile
import xml.etree.ElementTree as ET
import xml.dom.minidom

from rauth import OAuth1Service, OAuth2Service
from requests.exceptions import ConnectionError

from YahooSports.util import eprint
from YahooSports.exceptions import OAuthExpired, OAuth401Error


def _read_auth_keys(filename):
    #return dictionary from auth_keys.txt - simple colon delimited format
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
    """default rauth implementation needs a custom decoder for Yahoo's auth session"""
    rv = json.loads(json_struct)
    assert not hasattr(refresh_token_recipient, 'refresh_token')
    refresh_token_recipient.refresh_token = rv['refresh_token']
    eprint("refresh_token is {}".format(rv['refresh_token']))
    return rv


class YahooOAuth1Urls(object):
    url_get_token = 'https://api.login.yahoo.com/oauth/v2/get_token'
    url_request_auth = 'https://api.login.yahoo.com/oauth/v2/request_auth'
    url_get_request_token = 'https://api.login.yahoo.com/oauth/v2/get_request_token'


class YahooOAuth2Urls(object):
    url_get_token = 'https://api.login.yahoo.com/oauth2/get_token'
    url_request_auth = 'https://api.login.yahoo.com/oauth2/request_auth'


class YahooSession(object):
    url_base = "https://fantasysports.yahooapis.com/fantasy/v2/"

    def __init__(
            self, auth_filename=None, OAUTH_SHARED_SECRET=None, OAUTH_CONSUMER_KEY=None,
            oauth_version=2):
        """Use consumer key and shared secret to get an oauth session.  Ask user for PIN if the
        session is not stored in auth_filename or auth_filename is None
        """
        self.auth_filename = auth_filename
        self.session = None
        self.yahoo_oauth_service = None
        self.request_token = None
        self.request_token_secret = None
        self.oauth_version = oauth_version

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
            #load session
            with open(auth_session_file, 'rb') as pickle_file:
                self.session = pickle.load(pickle_file)

    def oath_1_service(self):
        return OAuth1Service(
            name='yahoo',
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            base_url=YahooSession.url_base,
            authorize_url=YahooOAuth1Urls.url_request_auth,
            access_token_url=YahooOAuth1Urls.url_get_token,
            request_token_url=YahooOAuth1Urls.url_get_request_token)

    def oath_2_service(self):
        return OAuth2Service(
            name="yahoo",
            client_id=self.consumer_key,
            client_secret=self.consumer_secret,
            base_url=YahooSession.url_base,
            authorize_url=YahooOAuth2Urls.url_request_auth,
            access_token_url=YahooOAuth2Urls.url_get_token)

    def auth_url(self):
        """reset self.session and return the auth URL that should be given to enter_pin()"""
        if self.oauth_version == 1:
            self.yahoo_oauth_service = self.oath_1_service()
            self.request_token, self.request_token_secret =\
                self.yahoo_oauth_service.get_request_token(data={'oauth_callback': "oob"})
            auth_url = self.yahoo_oauth_service.get_authorize_url(self.request_token)
        else:
            self.yahoo_oauth_service = self.oath_2_service()  # pylint: disable=R0204
            params = {'redirect_uri': 'oob', 'response_type': 'code'}
            auth_url = self.yahoo_oauth_service.get_authorize_url(**params)
        return auth_url

    def enter_pin(self, pin):
        """enter pin to get a new valid session.  save the session if we've specified an
        auth_filename"""
        if self.oauth_version == 1:
            self.session = self.yahoo_oauth_service.get_auth_session(
                self.request_token, self.request_token_secret, method='POST',
                data={'oauth_verifier': pin})
        else:
            data = {'code': "{}".format(pin), 'grant_type': 'authorization_code',
                    'redirect_uri': 'oob'}
            self.session = self.yahoo_oauth_service.get_auth_session(
                data=data,
                decoder=lambda x: _yahoo_oauth_response_decoder(x, self.yahoo_oauth_service))
        self.save_session()

    def refresh_session(self):
        """OAuth2 only.  Refresh session using the long-lived 'refresh_token' from Yahoo."""
        assert hasattr(self.yahoo_oauth_service, 'refresh_token')
        assert self.oauth_version == 2

        eprint("session expired.  refreshing.")

        refresh_data = {'refresh_token': "{}".format(self.yahoo_oauth_service.refresh_token),
                        'grant_type': 'refresh_token',
                        'redirect_uri': 'oob'}
        self.session = self.yahoo_oauth_service.get_auth_session(
            data=refresh_data,
            decoder=lambda x: _yahoo_oauth_response_decoder(x, self.yahoo_oauth_service))
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
            response = self.session.get("http://fantasysports.yahooapis.com/fantasy/v2/game/223")
        except ConnectionError:
            return False
        return response.ok

    def get_raw(self, url, **kwargs):
        """
        return the text value from session.get().  URL is a snippet appended onto session.url_base

        example:  session.get("game/nfl/stat_categories")

        Raises:
            OAuthExpired:   A special 401 error.  session must be refreshed with
                            .refresh_session() [OAuth v2] or with .auth_url(),
                            .enter_pin()  [OAuth v1]
            OAuth401Error:  other OAuth errors as described at
                            https://developer.yahoo.com/oauth2/guide/errors/#id1
            requests.exceptions.RequestException:  all other requests errors
        """
        response = self.session.get(YahooSession.url_base + url, **kwargs)
        if not response.ok:
            # parse for oath_problem
            out = re.search(r'oauth_problem="([^"]+)', response.text)
            oauth_problem_code = None
            if out:
                oauth_problem_code = out.groups()[0]
            if response.status_code == 401:
                if oauth_problem_code == "token_expired":
                    raise OAuthExpired
                raise OAuth401Error(oauth_problem_code)
            response.raise_for_status()
        else:
            return response.text

    def get_raw_with_refresh(self, url, **kwargs):
        """ do get_raw but automatically try refreshing the session token if we get a 401
        """
        try:
            return self.get_raw(url, **kwargs)

        except OAuthExpired as e:
            if self.oauth_version == 2:
                self.refresh_session()
                return self.get_raw(url, **kwargs)
            else:
                raise e

    def get(self, url, **kwargs):
        """
        return a pretty-formatted xml string from session.get.  Eliminate the global namespace from
        the top level element so that element tags are "clean" after parsing with
        xml.etree.ElementTree or lxml i.e. without the namespace in brackets.

        :returns: pretty-formatted xml string
        :rtype: utf-8 encoded string

        """
        raw = self.get_raw_with_refresh(url, **kwargs)
        root_obj = ET.fromstring(raw)

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

