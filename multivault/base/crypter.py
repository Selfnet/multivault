#!/usr/bin/env python3
# @author: marcelf
'''
Crypts files with gnupg software
'''

import os
import sys
import glob
try:
    import gpg
except ImportError:
    print("python-gpgme package not installed")
    print("Install it from your OS repositories.")
from hkp4py import KeyServer
from multivault.base.config import config
from multivault.utilities import util_ldap
from multivault.utilities import util_crypt

HOME = config.gpg['key_home']
util_crypt.create_gnupghome(path=HOME)
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
                  key in sudoers if not isinstance(key, str)]
    with gpg.Context(armor=True, home_dir=HOME) as gnupg:
        if files:
            for listed_file in files:
                if os.path.exists(listed_file):
                    with open(listed_file, 'r') as plain:
                        with open("{}.gpg".format(listed_file), 'w') as crypted:
                            gnupg.encrypt(plain, always_trust=True,
                                          recipients=recipients, sink=crypted, sign=False)
                            _remove_file(listed_file)
                    print("Encrypt The File {} To {}".format(
                        listed_file, "{}.gpg".format(listed_file)))

                else:
                    print("{} does not exist, so not encrypted!".format(listed_file))
        elif passwords:
            for length, listed_file in passwords:
                password = util_crypt.password_generator(size=int(length))
                with open("{}.gpg".format(listed_file), 'w') as crypted:
                    gnupg.encrypt(password.encode(sys.stdout.encoding),
                                  recipients=recipients, sink=crypted, sign=False, always_trust=True)
                    del(password)
                print("Create Password File {}".format(
                    "{}.gpg".format(listed_file))
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
# private: map_sudoers_to_fingerprints
# ================================================================


def _map_sudoers_to_fingerprints(sudoers):
    '''
        Map sudoers or admins to their keys
        @param sudoers   [(sudoer,fingerprint), ...]

        @return sudoers  [(sudoer, _gpgme_key), ...]
    '''

    sudoers = [[ldap_name, fingerprint] for ldap_name, fingerprint in sudoers]
    serv = KeyServer(config.gpg['key_server'])
    for sudoer in sudoers:
        keys = serv.search("0x{}".format(sudoer[1]),exact=True)
        if not keys:
            pass
        else:
            for key in keys:
                with gpg.Context(armor=True, home_dir=HOME) as gnupg:
                    _ = gnupg.op_import(key.key.encode('ascii'))
                    sudoer[1] = gnupg.get_key(str(sudoer[1]), secret=False)
                    sudoer[1] = sudoer[1]
                break
    sudoers = [(sudoer[0], sudoer[1]) for sudoer in sudoers]
    return sudoers
