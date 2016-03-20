Yahoo Sports API
================

Use the rauth library to interact with the Yahoo Sports Fantasy Football API.

Register your app:

https://developer.yahoo.com/apps/create

Verify your app's settings match consumer_secret and consumer_key in auth_keys.txt:

![My Apps Screenshot](/../screenshots/apps status.png?raw=true "My Apps Screenshot")

Verify your app has permissions to the "Fantasy Sports" data API

![My Apps Screenshot](/../screenshots/create a project.png?raw=true "My Apps Screenshot")

Usage
=====

A new interactive session:
```bash
>>> from YahooSports import YahooSession

>>> session = YahooSession()
>>> session.check()
Enter pin from the following URL:
https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token=abqfvr4
>>> session.enter_pin("abc123")
>>> brett_favre_xml = session.get("game/223/players;player_keys=223.p.1025").text
>>> print(brett_favre_xml)
<?xml version="1.0" encoding="UTF-8"?>
<fantasy_content xml:lang="en-US" yahoo:uri="http://fantasysports.yahooapis.com/fantasy ...
...
```

Creating a saved session: 
```python
from YahooSports import YahooSession

session = YahooSession(auth_filename="auth_keys.txt")
if not session.is_live_session():
    url = session.auth_url()
    print("Go to URL:")
    print(url)
    pin = raw_input('Enter PIN from browser: ')
    session.enter_pin(pin)
```

Using a saved session: 
```python
from YahooSports import YahooSession

session = YahooSession(auth_filename="auth_keys.txt")
brett_favre_xml = session.get("game/223/players;player_keys=223.p.1025").text
print(brett_favre_xml)
```

auth_keys.txt format
====================

    consumer_secret: lxWCDkDlDJPWAu2vhu6SxbTN5RboujMklxWCDkDl
    consumer_key: bnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t--


If the YahooSession constructor is called with an auth_filename
argument the generated rauth.session.OAuth1Session object will be
pickled and stored in a temporary file, pointed to by
auth_session_file:

    consumer_secret: lxWCDkDlDJPWAu2vhu6SxbTN5RboujMklxWCDkDl
    consumer_key: bnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t--
    auth_session_file: /tmp/tmp0tab11

Subsequent constructions of YahooSession will attempt to use the
pickled OAuth1Session or create a new one if stale.

Security
========

Don't check in auth_keys.txt.

The pickled session object is created with restricted permissions in
/tmp but relying on that for session security may be a bad idea.
