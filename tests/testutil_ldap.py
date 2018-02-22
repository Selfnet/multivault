#!/usr/bin/env python3

'''
Test Module for the utility LDAP Module inside the ansible_multivault package

'''
import os
from ansible_multivault import util_ldap
from ansible_multivault import config
TESTING_FILE = 'multivault-gitlabtest.yml'
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CONF_PATH = os.path.join(DIR_PATH, TESTING_FILE)
config.init(conf_path=CONF_PATH)
# config.LDAP_METHOD = 'ldap3'



def testcreate_ldap_dc():
    '''
        Testing create_ldap_dc
    '''
    domain_component_dn = "github.com"
    domain_component = util_ldap.create_ldap_dc(domain_component_dn)
    print(domain_component_dn, "--> " + domain_component)
    assert domain_component == 'dc=github,dc=com'


def testcreate_filter():
    '''
        Testing create_filter function
    '''
    users = ["alpha", "beta"]
    assert util_ldap.create_filter(users) == '"(|(uid=alpha)(uid=beta))"'
