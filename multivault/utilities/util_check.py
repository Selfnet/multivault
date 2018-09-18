import re
import yaml
import os
import sys
from subprocess import check_output, CalledProcessError
from copy import deepcopy
from multivault.utilities import util_crypt
from multivault.base.config import config

IGNORED = ['ubuntu', 'debian', 'ubuntu_host', 'debian_host']
encrypter = re.compile(r"^:pubkey.*keyid (?P<encrypter>.*?)$", re.MULTILINE)
allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]

    return all(allowed.match(x) for x in hostname.split("."))


def parse_play(play_file, INVENTORY=None):
    MAPPING = {}
    with open(play_file, mode="r") as playbook:
        playbook = yaml.load(playbook)
        for task in playbook:
            if 'roles' in task.keys():
                if isinstance(task['hosts'], list):
                    hosts = task['hosts']
                elif isinstance(task['hosts'], str):
                    hosts = task['hosts'].lower().split(',')
                else:
                    print('Unhandleable Type!')

                if isinstance(task['roles'], list):
                    roles = task['roles']
                elif isinstance(task['roles'], str):
                    roles = task['roles'].lower().split(',')
                else:
                    print('Unhandleable Type!')
                hosts = [host.strip() for host in hosts]
                roles = [role.strip() for role in roles]
                div = set(hosts)-set(IGNORED)
                div = list(div)
                hosts = match(div, INVENTORY=INVENTORY)
                MAPPING = merge_hosts_to_roles(roles, MAPPING, hosts)
    return {k: v for k, v in MAPPING.items() if v}


def match(groups, INVENTORY=None):
    hosts = []
    for group in groups:
        if group.startswith('!'):
            pass
        else:
            try:
                hosts.append(INVENTORY.get_groups_dict()[group])
            except Exception:
                if len(group.split('.')) > 1:
                    hosts.append([group])
    return util_crypt.flatten(hosts)


def merge_hosts_to_roles(roles, MAPPING, hosts):
    for role in roles:
        if role in MAPPING.keys():
            for host in hosts:
                if host not in MAPPING[role]:
                    MAPPING[role].append(host)
        else:
            MAPPING[role] = []
            for host in hosts:
                if host not in MAPPING[role]:
                    MAPPING[role].append(host)
    return MAPPING


def read_message(file_to_read):
    try:
        with open(os.devnull, 'w') as devnull:
            output = check_output(['/usr/bin/env', 'gpg', '--homedir',
                                   config.gpg['key_home'], '--list-packets', file_to_read], stderr=devnull)
            output = output.decode(sys.stdout.encoding)
    except CalledProcessError as e:
        if e.returncode != 2:
            print(e)
        output = e.output.decode(sys.stdout.encoding)
    encrypters = encrypter.findall(output)
    return encrypters


def look_for_dependencies(mapping, workdir, roles_path="./roles"):
    MAPPING = deepcopy(mapping)
    for role, hosts in mapping.items():
        meta_path = os.path.join(workdir, roles_path, role, 'meta', 'main.yml')
        roles = get_meta_info(meta_path)
        MAPPING = merge_hosts_to_roles(roles, MAPPING, hosts)
    if mapping == MAPPING:
        return MAPPING
    else:
        return look_for_dependencies(MAPPING, workdir, roles_path=roles_path)


def get_roles(workdir, roles_path="./roles"):
    return [role for role in os.listdir(os.path.join(workdir, roles_path)) if role]


def remove_string(gpg_path, path):
    temp = 0
    for i in range(0, len(gpg_path)):
        if gpg_path[i] == path[i]:
            temp = i

    return path[temp+1:]


def get_meta_info(meta_path):
    if not os.path.exists(meta_path):
        return []
    roles = []
    with open(meta_path, 'r') as meta:
        meta_info = yaml.load(meta)
    if not meta_info:
        return []
    if 'dependencies' in meta_info.keys():
        if not meta_info['dependencies']:
            return []

        for dependency in meta_info['dependencies']:
            if isinstance(dependency, dict):
                roles.append(dependency.get('role', []))
            elif isinstance(dependency, str):
                roles.append(dependency)
    return list(set(roles))


def build_dependency_tree(workdir, roles, roles_path="./roles"):
    DEPENDENCY_TREE = {}
    for role in roles:
        meta_path = os.path.join(workdir, roles_path, role, 'meta', 'main.yml')
        DEPENDENCY_TREE[role] = get_meta_info(meta_path)
    return DEPENDENCY_TREE
