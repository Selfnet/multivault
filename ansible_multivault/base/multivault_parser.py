#!/usr/bin/env python3
'''
    Parser for the multivault CLI
'''
import argparse
import re
from pprint import PrettyPrinter

class Config(argparse.Action):
    '''
        defines behaviour of --config like --help or --version
    '''

    def __init__(self,
                 option_strings,
                 config=None,
                 *args,
                 **kwargs):
        super(Config, self).__init__(option_strings,
                                     default=argparse.SUPPRESS, *args, **kwargs)
        self.prettyp = PrettyPrinter(indent=4)
        self.config = config

    def __call__(self, parser, namespace, values, option_string=None):
        self.prettyp.pprint(self.config)
        parser.exit(0)


class PaswAction(argparse.Action):
    '''
        defines behaviour of -p /--password
    '''

    def __call__(self, parser, namespace, values, option_string=None):
        print(namespace)
        namespace.passwords.append(tuple(values))
        print(namespace.passwords)
        pattern = re.compile("^[-+]?[0-9]+$")
        if (not pattern.match(values[0])) or (int(values[0]) <= 10):
            parser.error('first needs to be element of N+ and longer than 10')
        elif (not namespace.users) and (not namespace.servers):
            parser.error(
                '-p/--password can only be used with -u/--users | -s/--servers before')
