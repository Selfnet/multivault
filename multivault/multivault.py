#!/usr/bin/env python3
#@author: marcelf
'''
    The multivault entrypoint module
'''
import sys
import argparse
from multivault.base import crypter
from multivault.utilities import util_crypt
from multivault.base.config import config
from multivault.base.multivault_parser import Config, PaswAction
from multivault import __version__ as VERSION

config.load_config()

def main():
    '''
        Main program entrypoint of multivault
    '''
    parser = argparse.ArgumentParser(
        prog='multivault',
        add_help=True,
        description='Multivault encrypts and ' +
        'decrypts sensible data for ansible roles.'
    )
    parser.add_argument(
        '--config',
        config=config.get_config(),
        action=Config,
        nargs=0,
        help="show program's configuration and exit."
    )
    parser.add_argument('--version', action='version',
                        version='%(prog)s: v.{}'.format(VERSION))
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument(
        '-s',
        '--servers',
        type=str,
        metavar='SERVER',
        nargs='+',
        help='encrypts for the admins of the specified servers'
    )
    group2.add_argument(
        '-u',
        '--users',
        metavar='USER',
        type=str,
        nargs='+',
        help='encrypts for the provided ldap usernames'
    )
    parser.add_argument(
        '-p',
        '--password',
        type=str,
        metavar=('LENGTH', 'FILENAME'),
        action=PaswAction,
        nargs=2,
        default=[],
        dest='passwords',
        help='creation of an encrypted password by every -p/--password'
    )
    parser.add_argument(
        '-f',
        '--files',
        type=str,
        metavar='FILE',
        nargs='+',
        help='a list of files to be encrypted or decrypted'
    )
    args = parser.parse_args()
    if args.servers:
        print("encrypt")
        if args.files or args.passwords:
            if args.files:
                crypter.encrypt(files=args.files, hostnames=args.servers,)
            if args.passwords:
                crypter.encrypt(passwords=args.passwords,
                                hostnames=args.servers)
        else:
            parser.print_usage()
    elif args.users:
        print("encrypt")
        if args.files or args.passwords:
            if args.files:
                crypter.encrypt(files=args.files, users=args.users)
            if args.passwords:
                crypter.encrypt(passwords=args.passwords, users=args.users)
        else:
            parser.print_usage()
    elif args.files:
        print("decrypt")
        crypter.decrypt(args.files)
    else:
        parser.print_usage()
