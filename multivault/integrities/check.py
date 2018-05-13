import configparser
import yaml
import os
from multivault.utilities import util_check
from multivault.utilities import util_crypt
from multivault.utilities import util_ldap
from multivault.base import config
from multivault.base import crypter
from pprint import pprint
try:
    from ansible.parsing.dataloader import DataLoader
    from ansible.inventory.manager import InventoryManager
    import ansible.playbook.play as play
except ImportError:
    print("The integrity module relies on ansible!")
    print("\tpip3 install ansible")
    exit(1)


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_all_users_and_subkeys():
    results = {}
    users = util_ldap.get('users', data=[''])
    if users:
        authorized = crypter._map_sudoers_to_fingerprints(users)
    else:
        authorized = {}
    for user, key in authorized:
        if not isinstance(key, str):
            results[user] = []
            for name, _ in dict(key.subkeys).items():
                results[user].append(name)
    return results


def init(workdir='/home/cellebyte/git/selfnet/playbooks'):
    workdir = os.path.join(workdir)
    config = configparser.ConfigParser()

    ansible_cfg = os.path.join(workdir, 'ansible.cfg')
    DEFAULT_INVENTORY = None
    ROLES_PATH = None
    USER_SUBKEYS = get_all_users_and_subkeys()
    config.read(ansible_cfg)
    for section in config:
        for key_pair in config[section]:
            if key_pair == 'inventory':
                DEFAULT_INVENTORY = config[section][key_pair]
            elif key_pair == 'roles_path':
                ROLES_PATH = config[section][key_pair]
            else:
                pass
    if not DEFAULT_INVENTORY:
        DEFAULT_INVENTORY = 'inventory.ini'
    if not ROLES_PATH:
        ROLES_PATH = './roles'

    inventory_file = os.path.join(workdir, DEFAULT_INVENTORY)
    roles_path = os.path.join(workdir, ROLES_PATH)
    INVENTORY = InventoryManager(loader=DataLoader(),
                                 sources=[inventory_file])
    return workdir, INVENTORY, roles_path, USER_SUBKEYS


def checkout_information(MAPPING, DEPENDENCY_TREE, workdir=None, roles_path=None):
    results = []
    for role, hosts in MAPPING.items():
        roles = DEPENDENCY_TREE[role]
        [ roles.append(role) for role in roles if DEPENDENCY_TREE[role] and not role in roles]
        gpg_path = os.path.join(workdir, roles_path, role, 'gpg')
        if os.path.exists(gpg_path):
            results.append(check_with_structure(role, hosts, gpg_path))
        for dep_role in roles:
            gpg_path = os.path.join(workdir, roles_path, dep_role, 'gpg')
            if os.path.exists(gpg_path):
                results.append(check_with_structure(dep_role, hosts, gpg_path))
    return results


def check_with_structure(role, hosts, gpg_path):
    results = {}
    for path, _, files in os.walk(gpg_path):
        for file in files:
            file_path = os.path.join(path, file)
            if file_path.endswith('.gpg'):
                minified_path = util_check.remove_string(
                    gpg_path+os.sep, file_path)
                splitted_path = minified_path.split(os.sep)
                to_be_encrypted_for = []
                if len(splitted_path) > 1:
                    for host in splitted_path:
                        if host.endswith('.gpg') and os.path.isfile(file_path):
                            results[file_path] = to_be_encrypted_for
                        elif util_check.is_valid_hostname(host):
                            to_be_encrypted_for.append(host)
                        else:
                            print('Unknown')
                else:
                    results[file_path] = hosts
    return results


def get_encrypters_from_file(informations):
    results = {}
    for information in informations:
        for path, _ in information.items():
            results[path] = list(util_check.read_message(path))
    return results


def get_encrypters_from_ldap(informations, USER_SUBKEYS):
    results = {}
    for information in informations:
        for path, hosts in information.items():
            authorized = util_ldap.get_authorized(
                [host.split('.')[0] for host in hosts])
            if not authorized:
                authorized = {}
            results[path] = []
            for user, _ in authorized:
                for uid, keys in USER_SUBKEYS.items():
                    if uid == user:
                        results[path].append({uid: keys})
    return results


def crossover(IS_ENCRYPTED_FOR, SHOULD_BE_ENCRYPTED_FOR, USER_SUBKEYS):
    for path, user_keys in SHOULD_BE_ENCRYPTED_FOR.items():
        keys = list(IS_ENCRYPTED_FOR[path])
        for user_key in user_keys:
            for user, ikeys in user_key.items():
                matched = False
                for ikey in ikeys:
                    if ikey in keys:
                        matched = True
                if not matched:
                    print(
                        bcolors.WARNING + 'WARNING\t:::\t{} not encrypted for {}'.format(path, user))
                else:
                    print(
                        bcolors.OKGREEN + 'OK\t:::\t{} correctly encrypted for {}'.format(path, user))
                    for ikey in ikeys:
                        try:
                            keys.remove(ikey)
                        except ValueError:
                            pass
        if len(keys) > 0:
            for key in keys:
                user = get_user(key, USER_SUBKEYS)
                if not user:
                    print(
                        bcolors.WARNING + 'WARNING\t:::\t{} encrypted for unknown key {}'.format(path, key))
                else:
                    print(
                        bcolors.FAIL + 'ERROR\t:::\t{} encrypted for user {}, no longer assigned on this file.(please fix!)'.format(path, user))

    pass


def get_user(key, USER_SUBKEYS):
    for user, keys in USER_SUBKEYS.items():
        if key in keys:
            return user
    return None


def check(workdir=None, playbook='all.yml'):
    if not workdir:
        workdir, INVENTORY, roles_path, USER_SUBKEYS = init()
    else:
        return "Not Implemented"
    playbook_file = os.path.join(workdir, playbook)
    mapping = util_check.parse_play(playbook_file, INVENTORY=INVENTORY)
    MAPPING = util_check.look_for_dependencies(mapping, workdir, roles_path)
    DEPENDENCY_TREE = util_check.build_dependency_tree(workdir, util_check.get_roles(workdir, roles_path=roles_path), roles_path=roles_path)
    pprint(DEPENDENCY_TREE)
    FILE_HOSTS = checkout_information(
        MAPPING, DEPENDENCY_TREE, workdir=workdir, roles_path=roles_path)
    IS_ENCRYPTED_FOR = get_encrypters_from_file(FILE_HOSTS)
    SHOULD_BE_ENCRYPTED_FOR = get_encrypters_from_ldap(
        FILE_HOSTS, USER_SUBKEYS)
    crossover(IS_ENCRYPTED_FOR, SHOULD_BE_ENCRYPTED_FOR, USER_SUBKEYS)


if __name__ == '__main__':
    config.load_config()
    check()
