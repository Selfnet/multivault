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
        if os.path.exists(listed_file) and listed_file.endswith(".gpg"):
            with open(listed_file, "rb") as decrypt_file_pt:
                with open(listed_file[:-4], "wb") as decrypted_file:
                    try:
                        gnupg.decrypt(
                            decrypt_file_pt,
                            verify=False,
                            sink=decrypted_file)
                    except (gpg.errors.GPGMEError, gpg.errors.DeryptionError) as e:
                        print("Decryption error:\n\t{}".format(e))
                        exit(1)
            print("Decrypt The File {} To {}".format(
                listed_file, listed_file[:-4]))
            _remove_file(listed_file)
        else:
            print("{} does not exist or has not ".format(
                listed_file) + ".gpg ending, so not decrypted!")


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
    print(sudoers)
    gnupg = gpg.Context(home_dir=HOME)
    sudoers = _map_sudoers_to_fingerprints(gnupg, sudoers)
    recipients = [key for _,
                  key in sudoers if type(key) is not str]
    if files:
        for listed_file in files:
            if os.path.exists(listed_file):
                with open(listed_file, "rb") as listed_file_pt:
                    with open("{}.gpg".format(listed_file), "wb") as encrypted_file:

                        _merged_encryption(
                            gnupg, listed_file_pt, recipients, encrypted_file)

                print("Encrypt The File {} To {}".format(
                    listed_file, "{}.gpg".format(listed_file)))
                _remove_file(listed_file)
            else:
                print("{} does not exist, so not encrypted!".format(listed_file))
    elif passwords:
        for length, listed_file in passwords:
            password = util_crypt.password_generator(size=int(length))
            with open("{}.gpg".format(listed_file), "wb") as encrypted_file:

                _merged_encryption(gnupg, password.encode(
                    sys.stdout.encoding), recipients, encrypted_file)

            print("Create Password File {}".format(
                "{}.gpg".format(
                    listed_file
                ))
            )
    else:
        print("Please use either passwords <or> files not both")
        exit(1)
# ================================================================
# private: remove_file
# ================================================================


def _remove_file(filename):
    '''
        Removes a file ignores if it is found or not
        @param filename      this should be the full path
    '''
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass

# ================================================================
# private: merged_encryption
# ================================================================


def _merged_encryption(gnupg, message, recipients, output):
    '''
        Encrypts passwords or files
        @param gnupg      gnupg gpg.Context()
        @param message    message to be encrypted
        @param recipients recipients for which will be encrypted
        @param output     the output stream
    '''
    try:
        gnupg.encrypt(
            message,
            recipients=recipients,
            always_trust=True,
            sign=False,
            sink=output)
    except (gnupg.errors.GPGMEError, gnupg.errors.EncryptionError) as e:
        print("Encryption error:\n\t{}".format(e))
        exit(1)

# ================================================================
# private: map_sudoers_to_fingerprints
# ================================================================


def _map_sudoers_to_fingerprints(gnupg, sudoers):
    '''
        Map sudoers or admins to their keys
        @param gnupg     gpg.Context
        @param sudoers   [(sudoer,fingerprint), ...]

        @return sudoers  [(sudoer, _gpgme_key), ...]
    '''

    sudoers = [[ldap_name, fingerprint] for ldap_name, fingerprint in sudoers]
    for sudoer in sudoers:
        if config.GPG_REPO and not config.GPG_KEYSERVER:
            key_file_path = os.path.join(
                config.KEY_PATH, '{}.gpg'.format(sudoer[0]))
            if os.path.exists(key_file_path):
                with open(key_file_path, "rb") as key_file_pt:
                    keylist = gnupg.keylist(source=key_file_pt)
                    sudoer[1] = [key for key in keylist]
            else:
                print("{} has no GPG Key!".format(sudoer[0]))
        else:
            keylist = gnupg.keylist(pattern=sudoer[1])
            for key in keylist:
                if sudoer[1] in key.fpr:
                    sudoer[1] = key

            if type(sudoer[1]) is str:
                keylist = gnupg.keylist(
                    pattern=sudoer[1],
                    mode=gpg.constants.keylist.mode.EXTERN)
                for key in keylist:
                    if sudoer[1] in key.fpr:
                        sudoer[1] = key
                if type(sudoer[1]) is str:
                    print("{} has no GPG Key on Server!".format(sudoer[0]))

    sudoers = [(sudoer[0], sudoer[1]) for sudoer in sudoers]
    return sudoers
