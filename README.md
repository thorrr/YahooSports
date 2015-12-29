Yahoo Sports API
================

Use the rauth library to interact with the Yahoo Sports Fantasy Football API.

Register your app:

https://developer.yahoo.com/apps/create

Verify your app's settings match consumer_secret and consumer_key in auth_keys.txt:

![My Apps Screenshot](apps status.png?raw=true "My Apps Screenshot")

Verify your app has permissions to the "Fantasy Sports" data API

![My Apps Screenshot](create a project.png?1000x600 "My Apps Screenshot")

Usage in Python:

    from YahooSports.yahoo_sports import YahooSession
    session = YahooSession(auth_filename="auth_keys.txt")
    brett_favre_xml = session.get("game/223/players;player_keys=223.p.1025").text
    print(brett_favre_xml)

auth_keys.txt example:

    consumer_secret: lxWCDkDlDJPWAu2vhu6SxbTN5RboujMklxWCDkDl
    consumer_key: bnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t--
