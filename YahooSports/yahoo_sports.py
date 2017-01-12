from __future__ import (absolute_import, division, print_function, unicode_literals)
from builtins import *

from os.path import isfile
import re
import pickle
import tempfile
import xml.etree.ElementTree as ET
import xml.dom.minidom

from rauth import OAuth1Service
from requests.exceptions import ConnectionError


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


class YahooSession(object):
    urlBase = "http://fantasysports.yahooapis.com/fantasy/v2/"

    def __init__(self, auth_filename=None, OAUTH_SHARED_SECRET=None, OAUTH_CONSUMER_KEY=None):
        """Use consumer key and shared secret to get an oauth session.  Ask user for PIN if the
        session is not stored in auth_filename or auth_filename is None
        """
        self.auth_filename = auth_filename
        self.session = None

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

    def auth_url(self):
        """reset self.session and return the auth URL that should be given to enter_pin()"""
        self.yahoo_oauth_service = OAuth1Service(
            consumer_secret=self.consumer_secret,
            consumer_key=self.consumer_key,
            name='yahoo',
            access_token_url='https://api.login.yahoo.com/oauth/v2/get_token',
            authorize_url='https://api.login.yahoo.com/oauth/v2/request_auth',
            request_token_url='https://api.login.yahoo.com/oauth/v2/get_request_token',
            base_url='https://api.login.yahoo.com/oauth/v2/')
        self.request_token, self.request_token_secret = self.yahoo_oauth_service.get_request_token(
            data={'oauth_callback': "oob"})
        auth_url = self.yahoo_oauth_service.get_authorize_url(self.request_token)
        return auth_url

    def enter_pin(self, pin):
        """enter pin to get a new valid session.  save the session if we've specified an
        auth_filename"""
        self.session = self.yahoo_oauth_service.get_auth_session(
            self.request_token, self.request_token_secret,
            method='POST', data={'oauth_verifier': pin})

        if self.auth_filename:
            self.save_session(self.auth_filename)

    def save_session(self, auth_filename):
        assert self.session
        pickle_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
        pickle_file_name = pickle_file.name
        pickle.dump(self.session, pickle_file)
        pickle_file.close()

        with open(auth_filename, 'w') as f:
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

    def get_raw(self, url):
        """
        return the text value from session.get().  URL is a snippet appended onto session.urlBase

        example:  session.get("game/nfl/stat_categories")
        """
        response = self.session.get(YahooSession.urlBase + url)
        if not response.ok:
            raise ValueError("response not okay:  response.status_code = {}".format(
                response.status_code))
        else:
            return response.text

    def get(self, url):
        """
        return a pretty-formatted xml string from session.get.  Eliminate the global namespace from
        the top level element so that element tags are "clean" after parsing with
        xml.etree.ElementTree or lxml i.e. without the namespace in brackets.

        :returns: pretty-formatted xml string
        :rtype: utf-8 encoded string

        """
        raw = self.get_raw(url)
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

