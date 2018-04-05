#!/usr/bin/env python3
'''
Test Module which Checks if all files that are pushed to gitlab
are encrypted the right way
'''
import os
import unittest
import re
import gnupg
import yaml
from pprint import PrettyPrinter
from multivault.utilities import util_crypt
from multivault.base import config
from multivault.utilities import util_ldap


TESTING_FILE = 'multivault-gitlabtest.yml'
ANSIBLE = None
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.join(DIR_PATH, "..", "..")
CONF_PATH = os.path.join(DIR_PATH, TESTING_FILE)
config.init(conf_path=CONF_PATH)
ANSIBLE_PATH = os.path.join(DIR_PATH, "..", "..", "all.yml")
INVENTORY_PATH = os.path.join(DIR_PATH, "..", "..", "inventory.ini")
KEY_PATH = os.path.join(DIR_PATH, "..", "..", "temp", "keys")
GNUPG_PATH = os.path.join(DIR_PATH, "..", "..", "temp", "keyring")
GNUPG = gnupg.GPG(gnupghome=GNUPG_PATH)
with open(ANSIBLE_PATH, "r") as ANSIBLE_PT:
    ANSIBLE = yaml.load(ANSIBLE_PT)
PATTERN = re.compile(
    r'^(?P<path>roles/(?P<role>.*?)/gpg/(?P<filename>.*?\.gpg))$', re.MULTILINE)
PATTERN2 = re.compile(r'^\s*(.*?)\.server\.selfnet\.de$', re.MULTILINE)
PATTERN3 = re.compile(r'^:pubkey.*?keyid (.*?)$', re.MULTILINE)

#config.LDAP_SSH_HOP = 'login'


class TestChangedFiles(unittest.TestCase):
    '''
    Test Class for the gpg check
    '''

    def test_changed_files(self):
        '''
        Gets the Information from the changed file and from ldap and the gpg repo
        Validates if a file is encrypted for the right users
        '''
        config.init(conf_path=CONF_PATH)
        util_crypt.update_git_repo(config.GPG_REPO, path=KEY_PATH)
        files = construct_gpg_information("master")
        printer = PrettyPrinter(indent=2)
        for file_info in files:
            print(file_info['filename'])
            print(
                "+--- Encrypted for {}:".format(file_info['encrypted_for']))
            users = extract_subkey_for_every_user(file_info['users'])
            if users:
                for user, data in users.items():
                    for key in data.keys():
                        if key in file_info['encrypted_for']:
                            users[user][key]['encrypted_for'] = True
                        else:
                            pass
                printer.pprint(users)
                for user, data in users.items():
                    if user == 'tobiass' or user == 'sebastiann' or user == 'jo':
                        self.assertFalse(check_encrypted_for_user(data))
                    else:
                        self.assertTrue(check_encrypted_for_user(data))
            else:
                pass


def check_encrypted_for_user(key_data):
    '''
    checks for an encryption with one key of an user:
    '''
    for key in key_data.keys():
        if key_data[key]['encrypted_for']:
            return True
        else:
            pass
    return False


def extract_subkey_for_every_user(key_information):
    '''
    Extracts the information out of the
    gnupg.GPG.scan_keys() inside of the file_info object
    '''
    subkeys = {}
    if not key_information:
        return None
    for user, data in key_information.items():
        subkeys[user] = {}
        if data:
            data = data[0]
            for subkey, expire_date in data['subkeys']:
                subkeys[user][subkey] = {}
                subkeys[user][subkey]['expire_date'] = expire_date
                subkeys[user][subkey]['encrypted_for'] = False
        else:
            data = None
    return subkeys


def get_hosts(group_name):
    '''
    Get the hosts out of the
    ansible inventori.ini file
    '''
    return extract_hosts(
        util_crypt.run_cmd(
            ["ansible",
             group_name,
             "-i",
             INVENTORY_PATH,
             "--list-hosts"]))


def get_file_info(file_path):
    '''
    extracts the information out of the gpg file
    given py
       @param file_path
    '''
    return extract_keys(util_crypt.run_cmd(["gpg", "--list-packets", "--list-only", file_path]))


def changed_files(base, ahead):
    '''
    returns all files that differ from base branch
        @param base  the base branch
        @param ahead the actual branch
        @return list_of_files by function @method extract()
    '''
    return extract(util_crypt.run_cmd(["git", "diff", "--name-only", base, ahead, "--"]))


def all_files(branch):
    '''
    returns all files tracked inside the given branch
        @param branch the branch to list the files of
        @return list_of_all_files @method extract()
    '''
    return extract(util_crypt.run_cmd(["git", "ls-tree", "-r", "--name-only", branch]))


def extract(output):
    '''
    Uses regex to extract files from cli
    should be used only in a method _files
        @param  output                  output of @method all_files or @method changed_files
        @return list_of_extracted_files
    '''
    return [m.groupdict() for m in PATTERN.finditer(output)]


def extract_hosts(output):
    '''
    extracts the hosts from cli output of @method get_hosts(...)
        @param  output of a subprocess call
        @return list_of_matching_hostnames
    '''
    if '[WARNING]:' in output:
        return None
    return PATTERN2.findall(output)


def extract_keys(output):
    '''
    extract the keys from the cli output of @method get_file_info()
        @param output   output of cli
        @return list_of_keys_encrypted_for
    '''
    return PATTERN3.findall(output)


def construct_file_host_role_mapping(files):
    '''
    Reads the all.yml file from ansible and
    substitutes the groups to hostname_lists
        @param  files   gpg files with extracted role
        @return dict    dict with files and their hostnames
    '''
    for playbook in ANSIBLE[1:]:
        hosts = playbook['hosts']
        roles = playbook['roles']
        for fil in files:
            if fil['role'] in roles:
                fil['hosts'] = get_hosts(hosts)
    return files


def construct_gpg_information(base, ahead="HEAD", whole=False):
    '''
    Merges all methods from above to an big
    dictionary
        @param  base            base branch
        @param  ahead           actual branch defaults to current HEAD of branch
        @param  whole           if set to true the whole indexed files are checked
        @return files_and_hosts big dictionary with much information about the files
    '''
    if whole:
        changed = all_files(base)
    else:
        if not ahead:
            return None
        changed = changed_files(base, ahead)
    files_and_hosts = construct_file_host_role_mapping(changed)
    for file_meta in files_and_hosts:
        if 'hosts' in file_meta:
            users = util_ldap.get_authorized(file_meta['hosts'])
        else:
            users = None
        file_meta['path'] = file_meta['path'].split('/')
        path = ROOT_PATH
        for part in file_meta['path']:
            path = os.path.join(path, part)
        file_meta['encrypted_for'] = get_file_info(path)
        gpg_mapping = {}
        if users:
            for user,_ in users:
                gpg_key_file = os.path.join(KEY_PATH, user + ".gpg")
                if os.path.exists(gpg_key_file):
                    gpg_mapping[user] = GNUPG.scan_keys(gpg_key_file)
                else:
                    gpg_mapping[user] = None
            file_meta['users'] = gpg_mapping
        else:
            file_meta['users'] = None
    return files_and_hosts


if __name__ == "__main__":
    unittest.main()
