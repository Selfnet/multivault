#!/usr/bin/env python3

'''
    Configuration Module for the multivault yaml config file
'''
import os
import sys
import yaml
from pathlib import Path
from voluptuous import Schema, Required, All, Invalid, MultipleInvalid


class Configuration():
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.ldap = {}
        self.schema = Schema(
            {
                'gpg': {
                    Required('key_server', default='hkp://pgp.ext.selfnet.de'): str,
                    Required('key_home', default='/tmp/keys'): str
                },
                Required('ldap'): All({
                    Required('url'): str,
                    'connection': {
                        'ssh_hop': str,
                        'forward_port': int
                    },
                    Required('user'): {
                        Required('ou', default='people'): str,
                        Required('uid', default='uid'): str,
                        Required('gpg', default='pgpFingerprint'): str,
                        'masters': [
                            self.__master()
                        ]
                    },
                    Required('admin'): {
                        Required('group_type', default='openldap'): str,
                        Required('ou'): str,
                        Required('cn'): str,
                        Required('member'): str
                    },
                    'dc': str,
                    'o': str,
                },
                    self.__ad_or_ldap)
            }
        )
        self.gpg = {}
        if not self.config_path:
            config_name = 'multivault.yml'

            system_config_path = os.path.join('/etc', config_name)
            user_dir_config_path = os.path.join(
                Path.home(), '.config', config_name)
            user_config_path = os.path.join(
                Path.home(), '.{}'.format(config_name))

            if os.path.exists(system_config_path):
                self.config_path = system_config_path
            if os.path.exists(user_dir_config_path):
                self.config_path = user_dir_config_path
            if os.path.exists(user_config_path):
                self.config_path = user_config_path
            if not self.config_path:
                print('No Configuration found under:')
                print('\t{}'.format(system_config_path))
                print('\t{}'.format(user_dir_config_path))
                print('\t{}'.format(user_config_path))
                sys.exit(1)
        self.load_config()

    def __ad_or_ldap(self, ad_or_ldap):
        if 'dc' in ad_or_ldap.keys() and 'o' in ad_or_ldap.keys():
            raise Invalid(
                'You cannot use Active Directory and OpenLDAP schema at the same time.')
        elif 'dc' not in ad_or_ldap.keys() and 'o' not in ad_or_ldap.keys:
            raise Invalid(
                'Please specify either AD or OpenLDAP Binddn')
        return ad_or_ldap

    def __master(self):
        return lambda v: self.__check_master(v)

    def __check_master(self, master):
        if len(master.keys()) > 1:
            raise Invalid(
                "You can only specify a dict with one key: value here.")
        if not isinstance(list(master.keys())[0], str) or not isinstance(list(master.values())[0], str):
            raise Invalid("Key and value must be string here.")
        return master

    def load_config(self):
        '''
            initialize the configuration
            @param conf_path configuration path to be loaded
        '''
        config_in_memory = None
        with open(self.config_path, 'r') as config:
            config_in_memory = yaml.load(config)
        try:
            config_in_memory = self.schema(config_in_memory)
            self.gpg = config_in_memory.get('gpg')
            self.ldap = config_in_memory.get('ldap')
        except MultipleInvalid as e:
            print(e)
            print('Config not valid')
            print('Please Check your config under {}'.format(self.config_path))
            sys.exit(1)
    def get_config(self):
        return {"gpg": self.gpg, 'ldap': self.ldap}

config = Configuration()
