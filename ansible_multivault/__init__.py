#!/usr/bin/env python3
'''
    This is the ansible-multivault package
'''
from . import commands
from .commands import config
__version__= config.VERSION