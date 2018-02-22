#!/usr/bin/env python3
#@author: marcelf
'''
    The multivault entrypoint module
'''
import sys
import argparse
from ansible_multivault import crypter
from ansible_multivault import util_crypt
from ansible_multivault import config
from ansible_multivault.multivault_parser import Config, PaswAction

config.init()


def main():
    '''
        Main program entrypoint of multivault
    '''

    parser = argparse.ArgumentParser(
        prog='ansible-multivault',
        add_help=True,
        description='Multivault encrypts and ' +
        'decrypts sensible data for ansible roles.'
    )
    parser.add_argument(
        '--config',
        config=config.CONFIG,
        action=Config,
        nargs=0,
        help="show program's configuration and exit."
    )
    parser.add_argument('--version', action='version',
                        version='%(prog)s: v.{}'.format(config.VERSION))
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument(
        '-s',
        '--servers',
        type=str,
        metavar='SERVER',
        nargs='+',
        help='gets the sudo-user/-s for the hostnames out of ldap'
    )
    group2.add_argument(
        '-u',
        '--users',
        metavar='USER',
        type=str,
        nargs='+',
        help='uses the keys of the given ldap users'
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
    if args.servers or args.users:
        if config.GPG_REPO and not config.GPG_KEYSERVER:
            if not util_crypt.update_git_repo(
                    config.GPG_REPO, path=config.KEY_PATH):
                sys.exit(1)
        else:
            config.GPG_REPO = None

    if args.servers:
        if args.files or args.passwords:
            if args.files:
                crypter.encrypt(files=args.files, hostnames=args.servers,)
            if args.passwords:
                crypter.encrypt(passwords=args.passwords,
                                hostnames=args.servers)
        else:
            parser.print_usage()
    elif args.users:
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


if __name__ == "__main__":
    main()
