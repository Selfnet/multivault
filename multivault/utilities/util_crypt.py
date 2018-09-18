#!/usr/bin/env python3
# @author: marcelf
'''
Utility class to connect to ldap and generate secure passwords
'''
ciphers256 = "TWOFISH CAMELLIA256 AES256"
ciphers192 = "CAMELLIA192 AES192"
ciphers128 = "CAMELLIA128 AES"
ciphersBad = "BLOWFISH IDEA CAST5 3DES"
digests = "SHA512 SHA384 SHA256 SHA224 RIPEMD160 SHA1"
compress = "ZLIB BZIP2 ZIP Uncompressed"

gpgconf = """# gpg.conf settings for key generation:
expert
allow-freeform-uid
allow-secret-key-import
trust-model tofu+pgp
tofu-default-policy unknown
enable-dsa2
enable-large-rsa
cert-digest-algo SHA512
default-preference-list {0} {1} {2} {3} {4} {5}
personal-cipher-preferences {0} {1} {2} {3}
personal-digest-preferences {4}
personal-compress-preferences {5}
""".format(ciphers256, ciphers192, ciphers128, ciphersBad, digests, compress)

agentconf = """# gpg-agent.conf settings for key generation:
default-cache-ttl 300
max-cache-ttl 500
"""

import os
import sys
import string
from random import SystemRandom
from subprocess import check_output, CalledProcessError

# ================================================================
# public: flatten
# ================================================================


def flatten(list_of_lists):
    '''
    Makes a list of lists flatten
    @param  l          list
    @return l          flattened list
    [[1,2,3][4,5,6]]
    gets
    [1,2,3,4,5,6]
    '''
    return [item for sublist in list_of_lists for item in sublist]

# ================================================================
# public: password_generator
# ================================================================


def password_generator(size=20, chars=string.ascii_letters + string.digits):
    '''
    generates random password with digits lower- and uppercase ascii
        @param size         length of password
        @param chars        chars to be select by random
        @return password    contains the generated password
    '''
    secrets = SystemRandom()
    # Use secrets instead of random, cause random is very predictable
    return ''.join(secrets.choice(chars) for _ in range(size))


def create_gnupghome(path):
    if not os.path.exists(path) is True:
        print("Creating the {0} directory.".format(path))
        os.mkdir(path)
        os.chmod(path, 0o700)
        with open("{0}/{1}".format(path, "gpg.conf"), "w") as f1:
            f1.write(gpgconf)
        os.chmod("{0}/{1}".format(path, "gpg.conf"), 0o600)
        with open("{0}/{1}".format(path, "gpg-agent.conf"), "w") as f2:
            f2.write(gpgconf)
        os.chmod("{0}/{1}".format(path, "gpg-agent.conf"), 0o600)
