import configparser
import yaml
import os
import copy
import json
from multivault.utilities import util_check
from multivault.utilities import util_crypt
from multivault.utilities import util_ldap
from multivault.base.config import config
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

INVENTORY = None


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
    users = util_ldap.get('users', data='all')
    if users:
        authorized = crypter._map_sudoers_to_fingerprints(users)
    else:
        authorized = {}
    for user, key in authorized:
        if not isinstance(key, str):
            results[user] = {}
            results[user]['key'] = key
            results[user]['subkeys'] = []
            for subkey in key.subkeys:
                results[user]['subkeys'].append(subkey.keyid)
    return results


def init(workdir='/home/cellebyte/git/selfnet/playbooks'):
    workdir = os.path.join(workdir)
    ansible_config = configparser.ConfigParser()

    ansible_cfg = os.path.join(workdir, 'ansible.cfg')
    DEFAULT_INVENTORY = None
    ROLES_PATH = None
    USER_SUBKEYS = get_all_users_and_subkeys()
    # USER_SUBKEYS = None
    ansible_config.read(ansible_cfg)
    for section in ansible_config:
        for key_pair in ansible_config[section]:
            if key_pair == 'inventory':
                DEFAULT_INVENTORY = ansible_config[section][key_pair]
            elif key_pair == 'roles_path':
                ROLES_PATH = ansible_config[section][key_pair]
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
        gpg_path = os.path.join(workdir, roles_path, role, 'gpg')
        if os.path.exists(gpg_path):
            results.append(check_with_structure(role, hosts, gpg_path))
    roles_with_gpg = [result['role'] for result in results]
    for result in results:
        role = result['role']
        hosts = result['hosts']
        dependency_roles = DEPENDENCY_TREE[role]
        for dependency_role in dependency_roles:
            if dependency_role in roles_with_gpg:
                gpg_role = [
                    result for result in results if result['role'] == dependency_role][0]
                pprint(gpg_role)
                for _, information in gpg_role['files'].items():
                    for host in hosts:
                        if host not in information['hosts'] and hosts == information['hosts']:
                            information['hosts'].append(host)
                pprint(role)
                print('---------------------------')
                pprint(gpg_role)
    return results


def check_with_structure(role, hosts, gpg_path):
    results = {}
    results['role'] = role
    results['hosts'] = hosts
    results['files'] = {}
    for path, _, files in os.walk(gpg_path):
        for file in files:
            file_path = os.path.join(path, file)
            if file_path.endswith('.gpg'):
                minified_path = util_check.remove_string(
                    gpg_path+os.sep, file_path)
                splitted_path = minified_path.split(os.sep)
                to_be_encrypted_for = []
                results['files'][file_path] = {}
                if len(splitted_path) > 1:
                    for host in splitted_path:
                        # host is an encrypted file and not a host
                        if host.endswith('.gpg') and os.path.isfile(file_path):
                            results['files'][file_path]['hosts'] = to_be_encrypted_for
                        elif util_check.is_valid_hostname(host) and host in util_check.match(['all'], INVENTORY):
                            to_be_encrypted_for.append(host)
                        else:
                            results['files'][file_path]['hosts'] = hosts
                            break
                else:
                    results['files'][file_path]['hosts'] = hosts
    return results


def get_encrypters_from_file(informations):
    for information in informations:
        for path, _ in information['files'].items():
            print("Analyzing File: {}".format(path))
            information['files'][path]['encrypters'] = list(
                util_check.read_message(path))
    return informations


def get_encrypters_from_ldap(informations, USER_SUBKEYS):
    for information in informations:
        for path in information['files'].keys():
            hosts = [host.split('.')[0]
                     for host in information['files'][path]['hosts']]
            authorized = util_ldap.get_authorized(hosts)
            if not authorized:
                authorized = {}
            information['files'][path]['sudoers'] = []
            for user, _ in authorized:
                for uid, keys in USER_SUBKEYS.items():
                    if uid == user:
                        information['files'][path]['sudoers'].append(
                            {uid: keys})
    return informations


def crossover(informations, USER_SUBKEYS):
    for information in informations:
        print(bcolors.OKBLUE +
              'INFO\t:::\tCheck Encryption for role >> {} <<'.format(information['role']))
        for path, file_information in information['files'].items():
            keys = list(copy.deepcopy(file_information['encrypters']))
            print(bcolors.OKBLUE +
                  '\tINFO\t:::\tCheck for hosts >> {} <<'.format(file_information['hosts']))
            filename = '.../' + str(path.split(os.sep)[-1])
            for sudoer in file_information['sudoers']:
                for user, key_information in sudoer.items():
                    matched = False
                    for sub_key in key_information['subkeys']:
                        if sub_key in keys:
                            matched = True
                    if not matched:
                        print(
                            bcolors.WARNING + '\tWARNING\t:::\t{} not encrypted for user >> {} <<'.format(filename, user))
                    else:
                        print(
                            bcolors.OKGREEN + '\tOK\t:::\t{} correctly encrypted for user >> {} <<'.format(filename, user))
                        for sub_key in key_information['subkeys']:
                            try:
                                keys.remove(sub_key)
                            except ValueError:
                                pass
            if len(keys) > 0:
                for key in keys:
                    user = get_user(key, USER_SUBKEYS)
                    if not user:
                        print(
                            bcolors.WARNING + '\tWARNING\t:::\t{} encrypted for unknown key >> {} <<'.format(filename, key))
                    else:
                        print(
                            bcolors.FAIL + '\tERROR\t:::\t{} wrong encrypted for user >> {} <<(please fix!)'.format(filename, user))


def get_user(key, USER_SUBKEYS):
    for user, keys in USER_SUBKEYS.items():
        if key in keys:
            return user
    return None


def check(workdir=None, playbook='all.yml'):
    global INVENTORY
    if not workdir:
        workdir, INVENTORY, roles_path, USER_SUBKEYS = init()
    else:
        return "Not Implemented"
    # pprint(USER_SUBKEYS)
    playbook_file = os.path.join(workdir, playbook)
    mapping = util_check.parse_play(playbook_file, INVENTORY=INVENTORY)
    MAPPING = util_check.look_for_dependencies(mapping, workdir, roles_path)
    DEPENDENCY_TREE = util_check.build_dependency_tree(workdir, util_check.get_roles(
        workdir, roles_path=roles_path), roles_path=roles_path)
    # pprint(DEPENDENCY_TREE)
    FILE_HOSTS = checkout_information(
        MAPPING, DEPENDENCY_TREE, workdir=workdir, roles_path=roles_path)
    IS_ENCRYPTED_FOR = get_encrypters_from_file(FILE_HOSTS)
    SHOULD_BE_ENCRYPTED_FOR = get_encrypters_from_ldap(
        IS_ENCRYPTED_FOR, USER_SUBKEYS)
    # pprint(SHOULD_BE_ENCRYPTED_FOR)
    crossover(SHOULD_BE_ENCRYPTED_FOR, USER_SUBKEYS)


get_all_users_and_subkeys

if __name__ == '__main__':

    check()
