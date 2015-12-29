Yahoo Sports API
================

Use the rauth library to interact with the Yahoo Sports Fantasy Football API.

Register your app:

https://developer.yahoo.com/apps/create

Verify your app's settings match consumer_secret and consumer_key in auth_keys.txt:

![My Apps Screenshot](apps status.png?raw=true "My Apps Screenshot")

Verify your app has permissions to the "Fantasy Sports" data API

![My Apps Screenshot](create a project.png?raw=true "My Apps Screenshot")

Usage
=====

```python
from YahooSports.yahoo_sports import YahooSession

session = YahooSession(auth_filename="auth_keys.txt")
brett_favre_xml = session.get("game/223/players;player_keys=223.p.1025").text
print(brett_favre_xml)
```

auth_keys.txt format
====================

    consumer_secret: lxWCDkDlDJPWAu2vhu6SxbTN5RboujMklxWCDkDl
    consumer_key: bnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t--


If the YahooSession constructor is called with auth_filename the
session object will be pickled and stored in a temporary file, pointed
to in auth_filename.  Subsequent constructions of YahooSession will
attempt to use the pickled session or create a new one if stale.

Security
========

Don't check in auth_keys.txt.

The pickled session object is created with restricted permissions in
/tmp but relying on that for session security may be a bad idea.
