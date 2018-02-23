#!/usr/bin/env python3
#@author: marcelf
'''
Crypts files with gnupg software
'''

import os
import getpass
import gnupg
from multivault.base import config
from multivault.utilities import util_ldap
from multivault.utilities import util_crypt

HOME = '/tmp/gnupg_home'

# ================================================================
# public: decrypt
# ================================================================


def decrypt(files):
    '''
    decrypt all files given by the constructor of this class
        @param key_fingerprint  fingerprint of recipient
        @param files            files containing full
                                path to files including .gpg
                                in $filename
    '''
    gpg = gnupg.GPG()
    gpg.encoding = 'utf-8'
    if 'nt' in os.name:
        passphrase = getpass.win_getpass(prompt='GPG_PASSWORD: ')
    else:
        passphrase = getpass.unix_getpass(prompt='GPG_PASSWORD: ')

    for listed_file in files:
        if os.path.exists(listed_file):
            print(listed_file)
            with open(listed_file, "rb") as decrypt_file_pt:
                status = gpg.decrypt_file(decrypt_file_pt,
                                          passphrase=passphrase,
                                          output=listed_file[:-4])
                if not status.ok:
                    print('status: ', status.status)
                    exit(1)
                else:
                    os.remove(listed_file)
            print(listed_file[:-4])
        else:
            print(listed_file + " does not exist, so not decrypted!")

# ================================================================
# public: encrypt
# ================================================================


def encrypt(files=None, passwords=None, hostnames=None, users=None):
    '''
    encrypt all files given by the constructor of this class
        @param  files        list of files to be encrypted
        @param  passwords    list of password files to be created
        @param  hostnames    list of cn names in ldap of hosts
        @param  users        list of uids of users from ldap
    '''
    if hostnames:
        sudoers = util_ldap.get_authorized(hostnames)
    elif users:
        sudoers = util_ldap.get('users', data=users)
    else:
        print("Please define either users <or> hosts to be encrypted for!")
        exit(1)
    gpg = gnupg.GPG(gpgbinary='gpg', gnupghome=HOME)
    gpg.encoding = 'utf-8'
    sudoers = _map_sudoers_to_fingerprints(gpg, sudoers)
    recipients = [fingerprint for _,
                  fingerprint in sudoers if '[]' not in fingerprint  # weird behaviour of lists
                  or '' not in fingerprint]
    print(sudoers)

    if files:
        for listed_file in files:
            print(listed_file)
            if os.path.exists(listed_file):
                with open(listed_file, "rb") as listed_file_pt:
                    status = gpg.encrypt(listed_file_pt.read(),
                                         recipients,
                                         always_trust=True,
                                         output='{}.gpg'.format(listed_file))
                _status_print(status, recipients, listed_file)
            else:
                print("{} does not exist, so not encrypted!".format(listed_file))
    elif passwords:
        for length, listed_file in passwords:
            password = util_crypt.password_generator(size=int(length))
            status = gpg.encrypt(password, recipients, always_trust=True,
                                 output="{}.gpg".format(listed_file))
            _status_print(status, recipients, listed_file, file=False)
    else:
        print("Please use either passwords <or> files not both")
        exit(1)


# ================================================================
# private: status_print
# ================================================================
def _status_print(status, recipients, listed_file, file=True):
    '''
        Print status information if status not ok
    '''
    if not status.ok:
        print('recipients: ', recipients)
        print('status: ', status.status)
        exit(1)
    else:
        print("{}.gpg".format(listed_file))
        if file:
            os.remove(listed_file)

# ================================================================
# private: map_sudoers_to_fingerprints
# ================================================================


def _map_sudoers_to_fingerprints(gpg, sudoers):
    fingerprints = []

    sudoers = [[ldap_name, fingerprint] for ldap_name, fingerprint in sudoers]
    for sudoer in sudoers:
        if config.GPG_REPO and not config.GPG_KEYSERVER:
            key_file_path = os.path.join(
                config.KEY_PATH, '{}.gpg'.format(sudoer[0]))
            if os.path.exists(key_file_path):
                with open(key_file_path, "r") as key_file_pt:
                    result = gpg.import_keys(key_file_pt.read())
                    sudoer[1] = [
                        fingerprint for fingerprint in result.fingerprints][0]
            else:
                print("{} has no GPG Key!".format(sudoer[0]))
        else:
            result = gpg.recv_keys(config.GPG_KEYSERVER, sudoer[1])
            if not result.fingerprints:
                print("{} has no GPG Key on Server!".format(sudoer[0]))
            else:
                fingerprints.append(
                    [fingerprint for fingerprint in result.fingerprints])

    sudoers = [(sudoer[0], sudoer[1]) for sudoer in sudoers]
    return sudoers
