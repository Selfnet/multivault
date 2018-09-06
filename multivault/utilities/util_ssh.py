#!/usr/bin/env python3

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
This script creates an SSH Local Forward Tunnel to an
LDAP Server via its Standard Ports for ldap:// and ldaps://
"""

import getpass
import os
import re
import socket
import select
import threading
try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

import sys
from contextlib import contextmanager
import paramiko
from multivault.base.config import config

class ForwardServer (SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler (SocketServer.BaseRequestHandler):

    def handle(self):
        try:
            chan = self.ssh_transport.open_channel(
                'direct-tcpip',
                (self.chain_host,
                 self.chain_port),
                self.request.getpeername())
        except Exception as e:
            print(e)
            return
        if chan is None:
            return

        while True:
            r, _, _ = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        chan.close()
        self.request.close()


@contextmanager
def build_tunnel():
    '''
        Build Socks Tunnel to ssh_hop
    '''
    server = config.ldap['connection']['ssh_hop']
    remote = re.sub(r'^ldaps?:\/\/', '', config.ldap['url'])
    remote_port = 636 if config.ldap['url'].startswith('ldaps://') else 389

    client = paramiko.SSHClient()
    client._policy = paramiko.WarningPolicy()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_config = paramiko.SSHConfig()
    user_config_file = os.path.expanduser("~/.ssh/config")
    if os.path.exists(user_config_file):
        with open(user_config_file) as f:
            ssh_config.parse(f)

    user_config = ssh_config.lookup(server)
    cfg = {}
    if 'hostname' in user_config:
        cfg['hostname'] = user_config['hostname']
    if 'user' in user_config:
        cfg['username'] = user_config['user']
    if 'port' in user_config:
        cfg['port'] = user_config['port']
    if 'proxycommand' in user_config:
        cfg['sock'] = paramiko.ProxyCommand(user_config['proxycommand'])
    if 'identityfile' in user_config:
        path = os.path.expanduser(user_config['identityfile'][0])
        cfg['key_filename'] = user_config['identityfile']
        if not os.path.exists(path):
            raise Exception("Specified IdentityFile {}".format(path) +
                            " for {} in ~/.ssh/config not existing anymore.".format(server))
    try:
        client.connect(**cfg)
    except Exception as e:
        try:
            print('*** Failed to connect to {} with user {}\n{}'.format(
                cfg['hostname'], cfg['user'], e))
        except KeyError:
            print('*** SSH Tunnel Error')
            pass
        sys.exit(1)

    class SubHander (Handler):
        chain_host = remote
        chain_port = remote_port
        ssh_transport = client.get_transport()
    forwarder = ForwardServer(('127.0.0.1', config.ldap['connection']['forward_port']), SubHander)
    threading.Thread(target=forwarder.serve_forever).start()
    yield
    forwarder.shutdown()
    client.close()
