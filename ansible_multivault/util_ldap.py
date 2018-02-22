#!/usr/bin/env python3
'''
    Utility class to speak with ldap
    via ldap3 or ldapsearch
'''
import re
import sys
import subprocess


from ansible_multivault import util_crypt
from ansible_multivault import config
from ansible_multivault import util_ssh
NO_LDAP3 = False
try:
    from ldap3 import Server, Connection, ALL
except ImportError:
    NO_LDAP3 = True

# ================================================================
# public: get_users_and_gpg
# ================================================================


def get(option, data=None):
    '''
    Decides between ldap3 or ldapsearch
    '''
    data_type_ldapsearch = {
        'none': get_master_ldapsearch,
        'hostname': get_sudoers_for_host_ldapsearch,
        'users': get_users_and_gpg_ldapsearch,
    }
    data_type_ldap3 = {
        'none': get_master_ldap3,
        'hostname': get_sudoers_for_host_ldap3,
        'users': get_users_and_gpg_ldap3,
    }

    if 'ldapsearch' in config.LDAP_METHOD:
        return data_type_ldapsearch[option](data)
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
                    return data_type_ldap3[option](data, ldap_conn)
        else:
            with Connection(
                    Server(
                        config.LDAP_URL,
                        use_ssl=True,
                        get_info=ALL),
                    auto_bind=True) as ldap_conn:
                return data_type_ldap3[option](data, ldap_conn)
    else:
        print('Unknown method {}'.format(
            config.LDAP_METHOD) +
            'for\nldap:\n\tconnection:\n\t\tmethod:')
        sys.exit(1)

# ================================================================
# private: get_users_and_gpg_ldap3
# ================================================================


def get_users_and_gpg_ldap3(users, ldap_conn):
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
            create_filter_ldap3(users),
            attributes=['uid', config.LDAP_GPG_ATTRIBUTE]):
        users_fingerprints = [
            (str(entry['uid']),
             str(entry[config.LDAP_GPG_ATTRIBUTE]))
            for entry in ldap_conn.entries]
        return users_fingerprints
    return None

# ================================================================
# private: get_gpg_fingerprints_for_users_ldapsearch
# ================================================================


def get_users_and_gpg_ldapsearch(users):
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
                create_filter_ldapsearch(users),
                'uid',
                config.LDAP_GPG_ATTRIBUTE,
                "-LLL"])

    cmd = util_crypt.flatten(cmd)
    try:
        output = subprocess.check_output(cmd)
        output = output.decode(sys.stdout.encoding)
        users_fingerprints = re.findall(
            '^uid: (?P<uid>.*?)\n{}: (?P<fingerprint>.*?)$'.format(
                config.LDAP_GPG_ATTRIBUTE),
            output, re.MULTILINE)
    except subprocess.CalledProcessError as error:
        print(error.output, error.returncode)
        print("Cannot get sudo user!")
        return None
    print(users_fingerprints)
    return users_fingerprints

# ================================================================
# private: get_sudoers_for_host_ldapsearch
# ================================================================


def get_sudoers_for_host_ldapsearch(hostname):
    '''
    This function logs in to given login_url and runs ldapsearch on this
    host to get the sudo users for an cn=$hostname entry. If login_url is None
    this function tries to use ldapsearch directly on your computer to connect
    to an ldap server
        @param hostname     String containing common name of host in ldap
        @return sudo_list   List of sudoers for given hostname
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
                "{}={}".format(config.LDAP_CN, hostname),
                config.LDAP_SUDO,
                "-LLL"])

    cmd = util_crypt.flatten(cmd)
    sudo_list = None
    try:
        output = subprocess.check_output(cmd)
        output = output.decode(sys.stdout.encoding)
        sudo_list = re.findall(config.LDAP_SUDO + ': (.*?)\n', output)
    except subprocess.CalledProcessError as error:
        print("Cannot get sudo user!", error.returncode, error.output)
        return None

    return sudo_list

# ================================================================
# private: get_sudoers_for_host_ldap3
# ================================================================


def get_sudoers_for_host_ldap3(hostname, ldap_conn):
    '''
    This function uses the ldap3 connection to connect to the ldap server
    to get sudoers like in method get_sudoers_for_host_ldapsearch(...)
        @param hostname       common name or hostname of server inside ldap
        @param ldap_conn      Established LDAP Connection
        @param sudo      Flag which indicate sudo Users inside of LDAP
        @return sudo_list     List of sudoUsers for given hostname inside of ldap
    '''
    sudo_list = None
    if ldap_conn.search(create_ldap_dc(config.LDAP_DC), '({}={})'.format(
            config.LDAP_CN, hostname), attributes=[config.LDAP_SUDO]):
        sudo_list = [str(user)
                     for user in ldap_conn.entries[0][config.LDAP_SUDO]]
    return sudo_list

# ================================================================
# private: create_ldap_dc
# ================================================================


def create_ldap_dc(fqdn):
    '''
    Creates LDAP readable Domaincomponents from FQDN
        @param fqdn              secondlevel.toplevel fqdn (example.com)
        @return domain_component Domain Component LDAP format (dc=example,dc=com)
    '''
    fqdn = re.sub(r"\.", ",dc=", fqdn)
    domain_component = re.sub(r"^(\w|\W)", r"dc=\1", fqdn)
    return domain_component

# ================================================================
# private: create_filter_ldap3
# ================================================================


def create_filter_ldap3(users):
    '''
    Creates LDAP readable filter for all uids to get their entries
    '''
    user_filter = "(|"
    for user in users:
        user_filter = user_filter + "(uid={})".format(user)
    user_filter = user_filter + ")"
    return user_filter

# ================================================================
# private: create_filter_ldapsearch
# ================================================================


def create_filter_ldapsearch(users):
    '''
    Creates LDAP readable filter for all uids to get their entries
    '''
    user_filter = "'(|"
    for user in users:
        user_filter = user_filter + "(uid={})".format(user)
    user_filter = user_filter + ")'"
    return user_filter

# ================================================================
# private: get_head_association_ldapsearch
# ================================================================


def get_master_ldapsearch(data):
    '''
    This function logs in to given login_url and runs ldapsearch on this
    host to get the master users from ldap. If login_url is None
    this function tries to use ldapsearch directly on your computer to connect
    to an ldap server
        @param login_url      SSH_Hopping Server on which ldap is reachable
        @param url       The LDAP URL from config
        @param master    Flag which authenticates master Users inside of LDAP
        @return master_list   List of masters inside of ldap
    '''
    cmd = data
    cmd = []
    master_list = None
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
                "-LLL"])
    cmd = util_crypt.flatten(cmd)
    try:
        output = subprocess.check_output(cmd)
        output = output.decode(sys.stdout.encoding)
        master_list = re.findall(r'dn: uid=(.*?),ou.', output)
    except subprocess.CalledProcessError as error:
        print("Cannot get master user!", error.returncode, error.output)
    return master_list

# ================================================================
# private: get_head_association_ldap3
# ================================================================


def get_master_ldap3(data, ldap_conn):
    '''
    This function uses the ldap3 connection to connect to the ldap server
    and gets the master users out of it
        @param ldap_conn        Established LDAP Connection
        @param domain_component The Domain Component from create_ldap_dc(fqdn)
        @param master           Flag which authenticates master Users inside of LDAP
        @return master_list     List of masters inside of ldap
    '''
    master_list = data
    if ldap_conn.search(create_ldap_dc(config.LDAP_DC), '({}={})'.format(
            config.LDAP_MASTER_BEFORE,
            config.LDAP_MASTER_AFTER), attributes=['uid']):
        master_list = [str(entry['uid']) for entry in ldap_conn.entries]
    return master_list


# ================================================================
# public: get_authorized
# ================================================================


def get_authorized(hostnames):
    '''
        This function uses most of the config of multivault.yml inside the root directory.
        @param hostnames             list of hostnames
    '''
    sudoers = [get('hostname', data=hostname) for hostname in hostnames]
    masters = get('none')
    if not sudoers or not masters:
        print("Sudoers:", sudoers)
        print("Masters:", masters)
        print("An error ocurred by getting the required ldap information!")
        return None
    in_masters_but_not_in_sudoers = set(
        masters) - set(util_crypt.flatten(sudoers))
    authorized_list = list(set(util_crypt.flatten(sudoers))) + \
        list(in_masters_but_not_in_sudoers)
    if config.GPG_REPO and not config.GPG_KEYSERVER:
        return [(user, "") for user in authorized_list]
    return get('users', data=authorized_list)
