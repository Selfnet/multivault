#!/usr/bin/env python3

'''
    Module for ldap which creates search filter
    and the domain component
'''
import re

# ================================================================
# public: create_ldap_dc
# ================================================================


def create_ldap_dc(fqdn):
    '''
    Creates LDAP readable Domaincomponents from FQDN
        @param fqdn              secondlevel.toplevel fqdn (example.com)
        @return domain_component Domain Component LDAP format (dc=example,dc=com)
    '''
    fqdn = re.sub(r"\.", ",dc=", fqdn)
    return re.sub(r"^(\w|\W)", r"dc=\1", fqdn)

# ================================================================
# public: create_filter_ldap3
# ================================================================


def create_filter_ldap3(key, values):
    '''
    Creates LDAP readable filter for all uids to get their entries
    '''
    filter = "(|"
    for value in values:
        filter = filter + "({}={}*)".format(key, value)
    return filter + ")"

# ================================================================
# public: create_filter_ldapsearch
# ================================================================


def create_filter_ldapsearch(key, values):
    '''
    Creates LDAP readable filter for all uids to get their entries
    '''
    filter = "'(|"
    for value in values:
        filter = filter + "({}={}*)".format(key, value)
    return filter + ")'"