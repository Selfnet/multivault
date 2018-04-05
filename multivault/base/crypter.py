#!/usr/bin/env python3
#@author: marcelf
'''
Crypts files with gnupg software
'''

import os
import sys
import getpass
import pgpy
import glob
import gpg
import warnings
from multivault.hkp import KeyServer
from multivault.base import config
from multivault.utilities import util_ldap
from multivault.utilities import util_crypt

HOME = os.path.join('/tmp', 'gnupg_home')
warnings.filterwarnings("ignore") # ignore warnings
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
    with gpg.Context() as gnupg:
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
    print("\n".join(str(sudoer) for sudoer in sudoers))
    sudoers = _map_sudoers_to_fingerprints(sudoers)
    recipients = [key for _,
                  key in sudoers if type(key) is not str]
    if files:
        for listed_file in files:
            if os.path.exists(listed_file):
                with open("{}.gpg".format(listed_file), "wb") as encrypted_file:

                    _merged_encryption(
                        pgpy.PGPMessage.new(listed_file, file=True), recipients, encrypted_file)

                print("Encrypt The File {} To {}".format(
                    listed_file, "{}.gpg".format(listed_file)))
                _remove_file(listed_file)
            else:
                print("{} does not exist, so not encrypted!".format(listed_file))
    elif passwords:
        for length, listed_file in passwords:
            password = util_crypt.password_generator(size=int(length))
            with open("{}.gpg".format(listed_file), "wb") as encrypted_file:

                _merged_encryption(pgpy.PGPMessage.new(password.encode(
                    sys.stdout.encoding)), recipients, encrypted_file)

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


def _merged_encryption(PGPmessage, recipients, output_file):
    '''
        Encrypts passwords or files
        @param message         message to be encrypted
        @param recipients      recipients for which will be encrypted
        @param output_file     the output stream
    '''
    try:
        cipher = pgpy.constants.SymmetricKeyAlgorithm.AES256
        sessionkey = cipher.gen_key()
        enc_msg = recipients[0].encrypt(
            PGPmessage, cipher=cipher, sessionkey=sessionkey)
        if len(recipients) > 1:
            for recipient in recipients[1:]:
                enc_msg = recipient.encrypt(enc_msg, cipher=cipher, sessionkey=sessionkey)
            del sessionkey
        output_file.write(bytes(enc_msg))
    except Exception as e:
        print("Encryption error:\n\t{}".format(e))
        exit(1)

# ================================================================
# private: map_sudoers_to_fingerprints
# ================================================================


def _map_sudoers_to_fingerprints(sudoers):
    '''
        Map sudoers or admins to their keys
        @param sudoers   [(sudoer,fingerprint), ...]

        @return sudoers  [(sudoer, _gpgme_key), ...]
    '''

    sudoers = [[ldap_name, fingerprint] for ldap_name, fingerprint in sudoers]
    if config.GPG_REPO and not config.GPG_KEYSERVER:
        for sudoer in sudoers:
            key_file_path = os.path.join(
                config.KEY_PATH, '{}.gpg'.format(sudoer[0]))
            if os.path.exists(key_file_path):
                with open(key_file_path, "r") as key_file_pt:
                    key, _ = pgpy.PGPKey.from_blob(key_file_pt.read())
                    sudoer[1] = key
            else:
                pass
                # print("{} has no GPG Key!".format(sudoer[0]))
    else:
        serv = KeyServer(config.GPG_KEYSERVER)
        for sudoer in sudoers:
            keys = serv.search("0x{}".format(sudoer[1]))
            if not keys:
                pass
                # print("{} has no GPG Key!".format(sudoer[0]))
            else:
                for key in keys:
                    key, _ = pgpy.PGPKey.from_blob(key.key)
                    sudoer[1] = key
    sudoers = [(sudoer[0], sudoer[1]) for sudoer in sudoers]
    return sudoers
