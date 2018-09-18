#!/usr/bin/env python3

'''
    Module for ldap which creates search filter
    and the domain component
'''
import re

# ================================================================
# public: create_dc
# ================================================================


def create_dc(ldap):
    '''
    Creates LDAP readable Domaincomponents from FQDN
        @param ldap config       secondlevel.toplevel fqdn (example.com)
        @return domain_component Domain Component LDAP format (dc=example,dc=com)
        @return o                organization AD format (o=example.com)
    '''
    if ldap.get('dc', None):
        fqdn = re.sub(r"\.", ",dc=", ldap['dc'])
        return re.sub(r"^(\w|\W)", r"dc=\1", fqdn)
    elif ldap.get('o', None):
        return "o={}".format(ldap['o'])

# ================================================================
# public: create_filter_hosts
# ================================================================


def create_filter_hosts(key, values):
    return create_filter_users(key, values)

# ================================================================
# public: create_filter_users
# ================================================================


def create_filter_users(key, values):
    '''
    Creates LDAP readable filter for all uids specified on cli
    '''
    if isinstance(values, str):
        if values == 'all':
            return "({}=*)".format(key)
        else:
            return "({}={})".format(key, values)
    filter = "(|"
    for value in values:
        filter = filter + "({}={})".format(key, value)
    return filter + ")"

# ================================================================
# public: create_filter_masters
# ================================================================


def create_filter_masters(masters):
    '''
    Creates LDAP readable filter for all flags specified in config file
    '''
    filter = "(|"
    for master in masters:
        for key, value in master.items():
            filter = filter + "({}={})".format(key, value)
    return filter + ")"
