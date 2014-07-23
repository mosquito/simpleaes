# encoding: utf-8

from __future__ import absolute_import, print_function

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


__version__ = '0.4.2'
__author__ = 'Dmitry Orlov <me@mosquito.su>'


setup(name='simple_aes',
    version=__version__,
    author=__author__,
    author_email='me@mosquito.su',
    license="MIT",
    description="Very simple pycrypto AES helper.",
    platforms="all",
    url="http://github.com/mosquito/simpleaes",
    classifiers=[
      'Environment :: Console',
      'Programming Language :: Python',
    ],
    long_description=open('README.rst').read(),
    package_dir={'': 'src'},
    packages=[
      '.',
    ],
    install_requires=[
        'pycrypto'
    ],
)
