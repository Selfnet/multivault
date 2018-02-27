#!/usr/bin/env python3
#@author: marcelf
'''
Crypts files with gnupg software
'''

import os
import sys
import getpass
import gpg
from multivault.base import config
from multivault.utilities import util_ldap
from multivault.utilities import util_crypt

HOME = os.path.join('/tmp', 'gnupg_home')

# ================================================================
# public: decrypt
# ================================================================


def decrypt(files):
    '''
    decrypt all files given by the constructor of this class
        @param files            files containing full
                                path to files including .gpg
                                in $filename
    '''
    gnupg = gpg.Context()

    for listed_file in files:
        if os.path.exists(listed_file):
            print("Decrypt: {}".format(listed_file))
            with open(listed_file, "rb") as decrypt_file_pt:
                try:
                    decrypted_data, _, _ = gnupg.decrypt(
                        decrypt_file_pt, verify=False)
                except (gpg.errors.GPGMEError, gpg.errors.DeryptionError) as e:
                    print("Decryption error:\n{}".format(e))
                    exit(1)
                _write_file(decrypted_data, listed_file[:-4], encrypt=False)
            print("in {}".format(listed_file[:-4]))
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

    gnupg = gpg.Context(home_dir=HOME)
    sudoers = _map_sudoers_to_fingerprints(gnupg, sudoers)
    recipients = [key for _,
                  key in sudoers if type(key) is not str]

    if files:
        for listed_file in files:
            print(listed_file)
            if os.path.exists(listed_file):
                with open(listed_file, "rb") as listed_file_pt:
                    try:
                        encrypted_text, _, _ = gnupg.encrypt(
                            listed_file_pt, recipients=recipients, always_trust=True, sign=False, compress=True)
                    except (gnupg.errors.GPGMEError, gnupg.errors.EncryptionError) as e:
                        print("Decryption error:\n{}".format(e))
                        exit(1)
                    _write_file(encrypted_text, "{}.gpg".format(listed_file))
            else:
                print("{} does not exist, so not encrypted!".format(listed_file))
    elif passwords:
        for length, listed_file in passwords:
            password = util_crypt.password_generator(size=int(length))
            try:
                encrypted_text, _, _ = gnupg.encrypt(password.encode(
                    sys.stdout.encoding), recipients=recipients, always_trust=True, sign=False, compress=True)
            except (gpg.errors.GPGMEError, gpg.errors.EncryptionError) as e:
                print("Decryption error:\n{}".format(e))
                exit(1)
            _write_file(encrypted_text, "{}.gpg".format(listed_file))
    else:
        print("Please use either passwords <or> files not both")
        exit(1)


# ================================================================
# private: write_file
# ================================================================
def _write_file(content, filename, encrypt=True):
    '''
        Write File to disk
    '''
    with open(filename, "wb") as file_pt:
        file_pt.write(content)
        try:
            if encrypt:
                os.remove(filename[:-4])
            else:
                os.remove("{}.gpg".format(filename))
        except FileNotFoundError:
            pass

# ================================================================
# private: map_sudoers_to_fingerprints
# ================================================================


def _map_sudoers_to_fingerprints(gnupg, sudoers):

    sudoers = [[ldap_name, fingerprint] for ldap_name, fingerprint in sudoers]
    for sudoer in sudoers:
        if config.GPG_REPO and not config.GPG_KEYSERVER:
            key_file_path = os.path.join(
                config.KEY_PATH, '{}.gpg'.format(sudoer[0]))
            if os.path.exists(key_file_path):
                with open(key_file_path, "r") as key_file_pt:
                    result = gnupg.keylist(source=key_file_pt)
                    sudoer[1] = [
                        fingerprint for fingerprint in result[0].fpr]
            else:
                print("{} has no GPG Key!".format(sudoer[0]))
        else:
            keylist = gnupg.keylist(pattern=sudoer[1])
            for key in keylist:
                if sudoer[1] in key.fpr:
                    sudoer[1] = key

            if type(sudoer[1]) is str:
                keylist = gnupg.keylist(
                    pattern=sudoer[1], mode=gpg.constants.keylist.mode.EXTERN)
                for key in keylist:
                    if sudoer[1] in key.fpr:
                        sudoer[1] = key
                if type(sudoer[1]) is str:
                    print("{} has no GPG Key on Server!".format(sudoer[0]))

    sudoers = [(sudoer[0], sudoer[1]) for sudoer in sudoers]
    return sudoers
