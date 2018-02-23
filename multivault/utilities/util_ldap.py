#!/usr/bin/env python3
'''
    Utility class to speak with ldap
    via ldap3 or ldapsearch
'''
import re
import sys
import subprocess

from multivault.base import config
from multivault.utilities import util_ssh
from multivault.utilities import util_crypt
from multivault.utilities.util_filter import *

NO_LDAP3 = False
try:
    from ldap3 import Server, Connection, ALL
except ImportError:
    NO_LDAP3 = True

# ================================================================
# public: get
# ================================================================


def get(option, data=None):
    '''
    Decides between ldap3 or ldapsearch
    '''

    DATA_TYPE_LDAPSEARCH = {
        'none': _get_masters_ldapsearch,
        'hostnames': _get_users_and_gpg_for_hosts_ldapsearch,
        'users': _get_users_and_gpg_ldapsearch
    }
    DATA_TYPE_LDAP3 = {
        'none': _get_masters_ldap3,
        'hostnames': _get_users_and_gpg_for_hosts_ldap3,
        'users': _get_users_and_gpg_ldap3
    }

    if 'ldapsearch' in config.LDAP_METHOD:
        return DATA_TYPE_LDAPSEARCH[option](data)
    elif 'ldap3' in config.LDAP_METHOD:
        if NO_LDAP3:
            print("please install ldap3 via e.g. pip3 install" +
                  " ldap3 or use ldapsearch_wrapper from script")
            return None
        elif config.LDAP_SSH_HOP:
            with util_ssh.build_tunnel():
                with Connection(
                        Server(
                            "ldaps://localhost:%d" % (util_ssh.DEFAULT_PORT),
                            use_ssl=True,
                            get_info=ALL),
                        auto_bind=True) as ldap_conn:
                    return DATA_TYPE_LDAP3[option](data, ldap_conn)
        else:
            with Connection(
                    Server(
                        config.LDAP_URL,
                        use_ssl=True,
                        get_info=ALL),
                    auto_bind=True) as ldap_conn:
                return DATA_TYPE_LDAP3[option](data, ldap_conn)
    else:
        print('Unknown method {}'.format(
            config.LDAP_METHOD) +
            'for\nldap:\n\tconnection:\n\t\tmethod:')
        sys.exit(1)

# ================================================================
# private: _get_users_and_gpg_ldap3
# ================================================================


def _get_users_and_gpg_ldap3(users, ldap_conn):
    '''
    This function logs in to given login_url and runs ldapsearch on this
    host to get the fingerprints for given fingerprints
        @param users            ldap_uids of users
        @param login_url        login_url ssh_hop inside config
        @param url         url ldap server address
        @return dict(username=fingerprint)

    '''
    if ldap_conn.search(
            create_ldap_dc(config.LDAP_DC),
            create_filter_ldap3('uid', users),
            attributes=['uid', config.LDAP_GPG_ATTRIBUTE]):
        return [
            ((str(entry['uid']),
              str(entry[config.LDAP_GPG_ATTRIBUTE])))
            for entry in ldap_conn.entries]
    return None

# ================================================================
# private: _get_users_and_gpg
# ================================================================


def _get_users_and_gpg(cmd):
    try:
        output = subprocess.check_output(cmd)
        output = output.decode(sys.stdout.encoding)
        users_fingerprints = re.findall(
            '^uid: (?P<uid>.*?)\n{}: (?P<fingerprint>.*?)$'.format(
                config.LDAP_GPG_ATTRIBUTE),
            output, re.MULTILINE)
        return users_fingerprints
    except subprocess.CalledProcessError as error:
        print(error.output, error.returncode)
        print("Cannot get sudo user!")
    return None

# ================================================================
# private: _get_gpg_fingerprints_for_users_ldapsearch
# ================================================================


def _get_users_and_gpg_ldapsearch(users):
    '''
    This function logs in to given login_url and runs ldapsearch on this
    host to get the fingerprints for given fingerprints
        @param users            ldap_uids of users
        @return dict(username=fingerprint)

    '''
    cmd = []

    if config.LDAP_SSH_HOP:
        cmd.append(["ssh",
                    "-q",
                    config.LDAP_SSH_HOP])
    cmd.append(["ldapsearch",
                "-xH",
                config.LDAP_URL,
                '-b',
                create_ldap_dc(config.LDAP_DC),
                create_filter_ldapsearch('uid', users),
                'uid',
                config.LDAP_GPG_ATTRIBUTE,
                "-LLL"])

    cmd = util_crypt.flatten(cmd)
    return _get_users_and_gpg(cmd)

# ================================================================
# private: _get_sudoers_for_hosts_ldapsearch
# ================================================================


def _get_users_and_gpg_for_hosts_ldapsearch(hostnames):
    '''
    This function logs in to given login_url and runs ldapsearch on this
    host to get the sudo users for an cn=$hostname entry. If login_url is None
    this function tries to use ldapsearch directly on your computer to connect
    to an ldap server
        @param hostnames    List containing common namess of host in ldap
        @return sudo_list   List of sudoers for given hostnames
    '''
    cmd = []
    if config.LDAP_SSH_HOP:
        cmd.append(["ssh",
                    "-q",
                    config.LDAP_SSH_HOP])
    cmd.append(["ldapsearch",
                "-x",
                "-H",
                config.LDAP_URL,
                '-b',
                create_ldap_dc(config.LDAP_DC),
                create_filter_ldapsearch(
                    config.LDAP_HOST_ATTRIBUTE, hostnames),
                'uid',
                config.LDAP_GPG_ATTRIBUTE,
                "-LLL"])

    cmd = util_crypt.flatten(cmd)

    return _get_users_and_gpg(cmd)

# ================================================================
# private: _get_users_and_gpg_for_hosts_ldap3
# ================================================================


def _get_users_and_gpg_for_hosts_ldap3(hostnames, ldap_conn):
    '''
    This function uses the ldap3 connection to connect to the ldap server
    to get sudoers like in method _get_sudoers_for_hosts_ldapsearch(...)
        @param hostnames      common name or hostnames of server inside ldap
        @param ldap_conn      Established LDAP Connection
        @return sudo_list     List of sudoUsers for given hostnames inside of ldap
    '''
    if ldap_conn.search(
            create_ldap_dc(config.LDAP_DC),
            create_filter_ldap3(config.LDAP_HOST_ATTRIBUTE, hostnames),
            attributes=[
                'uid',
                config.LDAP_GPG_ATTRIBUTE
            ]):
        return [(str(entry['uid']), str(entry[config.LDAP_GPG_ATTRIBUTE])) for entry in ldap_conn.entries]
    return None

# ================================================================
# private: _get_masters_ldapsearch
# ================================================================


def _get_masters_ldapsearch(data):
    '''
    This function logs in to given login_url and runs ldapsearch on this
    host to get the master users from ldap. If login_url is None
    this function tries to use ldapsearch directly on your computer to connect
    to an ldap server
        @param data           Flag which authenticates master Users inside of LDAP
        @return master_list   List of masters inside of ldap
    '''
    _ = data
    cmd = []
    if config.LDAP_SSH_HOP:
        cmd.append(["ssh",
                    "-q",
                    config.LDAP_SSH_HOP])
    cmd.append(["ldapsearch",
                "-xH",
                config.LDAP_URL,
                '-b',
                create_ldap_dc(config.LDAP_DC),
                "{}={}".format(
                    config.LDAP_MASTER_BEFORE,
                    config.LDAP_MASTER_AFTER),
                'uid',
                config.LDAP_GPG_ATTRIBUTE,
                "-LLL"])
    cmd = util_crypt.flatten(cmd)

    return _get_users_and_gpg(cmd)

# ================================================================
# private: _get_masters_ldap3
# ================================================================


def _get_masters_ldap3(data, ldap_conn):
    '''
    This function uses the ldap3 connection to connect to the ldap server
    and gets the master users out of it
        @param data             Data to query to the function
        @param ldap_conn        Established LDAP Connection
        @return master_list     List of masters inside of ldap
    '''
    _ = data
    if ldap_conn.search(create_ldap_dc(config.LDAP_DC), '({}={})'.format(
            config.LDAP_MASTER_BEFORE,
            config.LDAP_MASTER_AFTER), attributes=['uid', config.LDAP_GPG_ATTRIBUTE]):
        return [(str(entry['uid']), str(entry[config.LDAP_GPG_ATTRIBUTE])) for entry in ldap_conn.entries]
    return None


# ================================================================
# public: get_authorized
# ================================================================


def get_authorized(hostnames):
    '''
        This function uses most of the config of multivault.yml inside the root directory.
        @param hostnames             list of hostnames
        @return authorized_list      list of people that should access the file
    '''
    sudoers = get('hostnames', data=hostnames)
    masters = get('none')
    if not sudoers or not masters:
        print("Sudoers:", sudoers)
        print("Masters:", masters)
        print("An error ocurred by getting the required ldap information!")
        return None
    in_masters_but_not_in_sudoers = set(
        masters) - set(sudoers)
    authorized_list = list(sudoers) + \
        list(in_masters_but_not_in_sudoers)
    if config.GPG_REPO and not config.GPG_KEYSERVER:
        return [(user, "") for user, _ in authorized_list]
    return authorized_list
