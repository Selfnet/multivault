#!/usr/bin/env python3
#@author: marcelf
'''
Utility class to connect to ldap and generate secure passwords
'''

import os
import sys
import string
from random import SystemRandom

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
