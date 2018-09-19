#!/usr/bin/env python3
'''
    Utility class to speak with ldap
    via ldap3
'''
import re
import sys
from multivault.base.config import config
from multivault.utilities import util_ssh
from multivault.utilities import util_crypt
from multivault.utilities.util_filter import *
from ldap3 import Server, Connection, ALL

# ================================================================
# public: get
# ================================================================


def get(option, data=None):
    '''
        get different informations
    '''

    LDAP3 = {
        'none': _get_masters,
        'hostnames': _get_users_and_gpg_for_hosts,
        'users': _get_users_and_gpg
    }

    if config.ldap.get('connection', None):
        with util_ssh.build_tunnel():
            with Connection(
                    Server(
                        "ldaps://localhost:{}".format(
                            config.ldap['connection']['forward_port']),
                        use_ssl=True,
                        get_info=ALL),
                    auto_bind=True) as ldap_conn:
                return LDAP3[option](data, ldap_conn)
    else:
        with Connection(
                Server(
                    config.ldap['url'],
                    use_ssl=True,
                    get_info=ALL),
                auto_bind=True) as ldap_conn:
            return LDAP3[option](data, ldap_conn)

# ================================================================
# private: _get_users_and_gpg_ldap3
# ================================================================


def _get_users_and_gpg(users, ldap_conn):
    '''
    This function logs in to given login_url and runs ldap3 on this
    host to get the fingerprints for given fingerprints
        @param users            ldap_uids of users
        @param ldap_conn        Established LDAP Connection
        @return list(set(username,fingerprint))

    '''
    if ldap_conn.search(
            'ou={},{}'.format(config.ldap['user']['ou'],
                              create_dc(config.ldap)),
            create_filter_users('uid', users),
            attributes=['uid', config.ldap['user']['gpg']]):
        return [
            ((str(entry['uid']),
              str(entry[config.ldap['user']['gpg']])))
            for entry in ldap_conn.entries]
    return None

# ================================================================
# private: _get_users_and_gpg_for_hosts
# ================================================================


def _get_users_and_gpg_for_hosts(hostnames, ldap_conn):
    '''
    This function uses the ldap3 connection to connect to the ldap server
    to get sudoers like in method _get_sudoers_for_hosts(...)
        @param hostnames      common name or hostnames of server inside ldap
        @param ldap_conn      Established LDAP Connection
        @return list(set(username, fingerprint))
    '''
    if ldap_conn.search("ou={},{}".format(
            config.ldap['admin']['ou'], create_dc(config.ldap)),
            create_filter_hosts(config.ldap['admin']['cn'], hostnames),
            attributes=[config.ldap['admin']['member']]):
        users = [entry[config.ldap['admin']['member']]
                 for entry in ldap_conn.entries]
        users = util_crypt.flatten(users)
        return _get_users_and_gpg(users, ldap_conn)
    return None


# ================================================================
# private: _get_masters
# ================================================================


def _get_masters(data, ldap_conn):
    '''
    This function uses the ldap3 connection to connect to the ldap server
    and gets the master users out of it
        @param data             Data to query to the function
        @param ldap_conn        Established LDAP Connection
        @return list(set(username,fingerprint))
    '''
    _ = data
    if ldap_conn.search('ou={},{}'.format(config.ldap['user']['ou'],
                                          create_dc(config.ldap)),
                        create_filter_masters(config.ldap['user']['masters']),
                        attributes=['uid', config.ldap['user']['gpg']]):
        return [(str(entry['uid']), str(entry[config.ldap['user']['gpg']])) for entry in ldap_conn.entries]
    return None


# ================================================================
# public: get_authorized
# ================================================================


def get_authorized(hostnames):
    '''
        This function uses most of the config of multivault.yml inside the root directory.
        @param hostnames             list of hostnames
        @return list(set(username,fingerprint))
    '''
    sudoers = get('hostnames', data=hostnames)
    masters = get('none')
    if not sudoers or not masters:
        print("Sudoers:", sudoers)
        print("Masters:", masters)
        print("An error ocurred by getting the required ldap information!")
        return None
    in_masters_but_not_in_sudoers = set(masters) - set(sudoers)
    authorized_list = list(sudoers) + list(in_masters_but_not_in_sudoers)
    return authorized_list
