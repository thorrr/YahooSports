Yahoo Sports API
================

Uses the rauth library to interact with the Yahoo Sports Fantasy Football API.

Usage:

    from YahooSports.yahoo_sports import YahooSession
    session = YahooSession(auth_filename="auth_keys.txt")
    brett_favre_xml = session.get("game/223/players;player_keys=223.p.1025").text
    print(brett_favre_xml)

auth_keys.txt example:

    consumer_secret: lxWCDkDlDJPWAu2vhu6SxbTN5RboujMklxWCDkDl
    consumer_key: bnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t6yuawMbnDS4RZd8mgeYJndVPBgr6gG2t--
