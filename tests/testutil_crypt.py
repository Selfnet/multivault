#!/usr/bin/env python3

'''
    Test Module for the utility Module inside the ansible_multivault package
'''
import os
from ansible_multivault import util_crypt
from ansible_multivault import config
TESTING_FILE = 'multivault-gitlabtest.yml'
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CONF_PATH = os.path.join(DIR_PATH, TESTING_FILE)
config.init(conf_path=CONF_PATH)

def testflatten():
    '''
        Testing flatten
    '''
    print("Flatten:")
    aaa = [1, 2, 3]
    bbb = [4, 5, 6]
    ccc = []
    ccc.append(aaa)
    ccc.append(bbb)
    print(ccc)
    assert [1, 2, 3, 4, 5, 6] == util_crypt.flatten(ccc)
    print(util_crypt.flatten(ccc))

def testpassword_generator():
    '''
        Testing password_generator
    '''
    assert util_crypt.password_generator()
    assert len(util_crypt.password_generator()) == 20

def testrun_cmd():
    '''
        Testing run_cmd
    '''
    assert util_crypt.run_cmd('hostname')

def testupdate_git_repo():
    '''
        Testing update_git_repo
    '''
    assert util_crypt.update_git_repo(config.GPG_REPO, config.KEY_PATH)
    assert util_crypt.update_git_repo(config.GPG_REPO, config.KEY_PATH)
