from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import *

from os.path import isfile
import re
import pickle
import tempfile

from rauth import OAuth1Service


def read_auth_keys(filename):
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


def get_pin_from_user_interaction(request_token, oauthService):
    auth_url = oauthService.get_authorize_url(request_token)
    print('Visit this URL in your browser:\n')
    print(auth_url)
    # webbrowser.open(auth_url) #this is awesome in windows but annoying in cygwin
    pin = raw_input('Enter PIN from browser: ')
    return pin


class YahooSession(object):
    urlBase = "http://fantasysports.yahooapis.com/fantasy/v2/"

    def __init__(self, auth_filename=None, OAUTH_SHARED_SECRET=None, OAUTH_CONSUMER_KEY=None):
        """Use consumer key and shared secret to get an oauth session.  Ask user for PIN if the session is
        not stored in auth_filename or auth_filename is None
        """
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
            auth_keys = read_auth_keys(auth_filename)
            self.consumer_secret = auth_keys['consumer_secret']
            self.consumer_key = auth_keys['consumer_key']
            auth_session_file = auth_keys.get('auth_session_file')

        if auth_session_file and isfile(auth_session_file):
            #load session
            with open(auth_session_file, 'rb') as pickle_file:
                self.session = pickle.load(pickle_file)
                if self.isLiveSession():
                    return
        print("saved session is stale.  Getting a full pin from the user")
        self.ask_for_pin_and_get_session()
        if auth_filename:
            self.save_session(auth_filename)

    def ask_for_pin_and_get_session(self):
        """reset self.session"""
        yahoo_oauth_service = OAuth1Service(
            consumer_secret=self.consumer_secret,
            consumer_key=self.consumer_key,
            name='yahoo',
            access_token_url='https://api.login.yahoo.com/oauth/v2/get_token',
            authorize_url='https://api.login.yahoo.com/oauth/v2/request_auth',
            request_token_url='https://api.login.yahoo.com/oauth/v2/get_request_token',
            base_url='https://api.login.yahoo.com/oauth/v2/')
        request_token, request_token_secret = yahoo_oauth_service.get_request_token(
            data={'oauth_callback': "oob"})
        pin = get_pin_from_user_interaction(request_token, yahoo_oauth_service)

        def get_auth_session(oauthService, request_token, request_token_secret, pin):
            return oauthService.get_auth_session(request_token, request_token_secret, method='POST',
                                                 data={'oauth_verifier': pin})

        self.session = get_auth_session(
            yahoo_oauth_service, request_token, request_token_secret, pin)

    def save_session(self, auth_filename):
        assert self.session
        pickle_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
        pickle_file_name = pickle_file.name
        pickle.dump(self.session, pickle_file)
        pickle_file.close()

        with open(auth_filename, 'w') as f:
            f.write("consumer_secret: {}\n".format(self.consumer_secret))
            f.write("consumer_key: {}\n".format(self.consumer_key))
            f.write("session_file: {}\n".format(pickle_file_name))

    def isLiveSession(self):
        response = self.session.get("http://fantasysports.yahooapis.com/fantasy/v2/game/223")
        if response.ok:
            return True
        else:
            return False

    def get(self, url):
        """
        return the text value from session.get().  URL is a snippet appended onto session.urlBase

        example:  session.get("game/nfl/stat_categories")
        """
        response = self.session.get(YahooSession.urlBase + url)
        if not response.ok:
            raise ValueError("response not okay:  response.status_code = {}".format(
                response.status_code))
        else:
            return response
