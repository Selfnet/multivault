#!/usr/bin/env python3
#@author: marcelf
'''
Utility class to connect to ldap and generate secure passwords
'''
import subprocess
import os
import sys
import string
NO_SECRETS = False

try:
    import secrets
except ImportError:
    NO_SECRETS = True

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
# public: run_cmd
# ================================================================


def run_cmd(cmd):
    '''
    runs command via subprocess and returns
    encoded output
    '''
    try:
        output = (subprocess.check_output(cmd))
        output = output.decode(sys.stdout.encoding)
    except subprocess.CalledProcessError:
        pass
    return output

# ================================================================
# public: update_git_repo
# ================================================================


def update_git_repo(repo_url, path):
    '''
    updates a git repository <- this is trivial
        @param repo_url     online address of key_repo
        @param path         path to the git repository
        @return bool        True or False
    '''
    if not os.path.exists(path):
        os.makedirs(path)
    if not os.path.exists(os.path.join(path, ".git")):
        output = run_cmd(["git", "clone", repo_url, path])
    else:
        try:
            output = subprocess.check_output(
                ["git", "-C", path, "pull"])
            output = output.decode(sys.stdout.encoding)
            print("Updated login-keys repository!")
        except subprocess.CalledProcessError:
            print("Cannot pull key-repo from git server! Fehler:\n " + output)
            return False
    return True

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
    if NO_SECRETS:
        print("You are using a Version prior than python3.6 so this fuńction" +
              " is using a pwgen wrapper!")
        try:
            output = subprocess.check_output(
                ['pwgen', '--secure', str(size)])
            output = output.decode(sys.stdout.encoding)
        except subprocess.CalledProcessError as error:
            print(error.returncode, error.output)
            return None
        return output[:-1]
    # Use secrets instead of random, cause random is very predictable
    return ''.join(secrets.choice(chars) for _ in range(size))
