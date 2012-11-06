#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='DjangoRestlessOAuth',
    version='0.0.1',
    author='Senko Rasic',
    author_email='senko.rasic@goodcode.io',
    description='OAuth1 provider support for DjangoRestless',
    license='MIT',
    url='http://goodcode.io/',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    install_requires=[
        'DjangoRestless>=0.0.3'
    ]
)
