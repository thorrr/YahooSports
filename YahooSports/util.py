from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *

import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

