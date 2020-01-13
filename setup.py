from setuptools import setup
from transip_rest_client.__version__ import __version__, __name__, __author__, __author_email__, __description__, \
    __license__

setup(
    name=__name__,
    version=__version__,
    packages=['transip_rest_client'],
    url='',
    license=__license__,
    author=__author__,
    author_email=__author_email__,
    description=__description__
)
