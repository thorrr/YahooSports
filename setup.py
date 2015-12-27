try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Yahoo Sports API',
    'author': 'Jason Bell',
    'url': '',
    'download_url': '',
    'author_email': 'jbellthor@gmail.com',
    'version': '0.1',
    'install_requires': ['pytest', 'rauth'],
    'packages': ['YahooSports'],
    'scripts': [],
    'name': 'YahooSports'
}

setup(**config)
