#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest
from YahooSports import YahooConnection


@pytest.mark.xfail
def test_yahoo_session():
    # TODO - add tests here
    session = YahooConnection()  # need arguments
