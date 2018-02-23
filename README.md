# multivault prior to use with ansible

This is only supported via python3 at the moment

## Setup normal

* install python3 via your packet managerto lookup
* then install the package

      pip install .

* to install the ansible_multivault package to your path.
* your almost there run `multivault --version` <<- if it works, nice!
* config is under `~/.config/.multivault.yml`
* or can be invoked by `multivault --config`

## Setup development

    pip install -e .[dev]

## Description

This is a CLI which connects to a ldap server.
It gathers user information from their to
get the actual admin users for all servers in our organization.

Based on this information it uses the gpg keys of this users
which can be provided by the ldap server itself or by a git
repository which has key files like $UID.gpg to encrypt the
given password or file with the right keys.

Ansible then uses a simple lookup module for the gpg encrypted
files. This is an alpha and not recommended to use in production.

### crypter encrypts and decrypts data via GPG

* requires
  * install gnupg | gnupg2 for that purpose with your preferred packet manager

  apt install gnupg
  pacman -S gnupg
  yum install gnupg

### util_ldap speaks with ldap

#### LDAP3 module

* to use ldap3 install with `ldap3` environment

      pip install -e .[ldap3]

* if u define `ssh_hop` inside the ldap section of
  the config `.multivault.yml` the command is run on
  the local machine and paramiko makes something like

      ssh -L 127.0.0.1:10000:ldap.example.com:636 login_host

* `ldap3` connects than against localhost:10000 and queries the server
* every request opens and closes a tcp connection to the ldap server

#### LDAPSEARCH command line wrapper

* you must install ldapsearch, if you are not using
  the option `ssh_hop` inside the `multivault.yml`
  it uses subprocess to call ldapsearch on your local computer

      sudo apt install ldap-utils
      pacman -S openldap

* if you define `ssh_hop` inside the ldap section of
  the config `.multivault.yml` the command is run on
  the server specified by the hostname. To get this to work,
  you must have login access to this server. SSH_CONFIG is also used
  by this method.

## For developers

    pip install -e .[dev]

* this installs the development environment of multivault
  * packages like
    * `pylint`
    * `pep8`
    * `autopep8`
    * `ldap3`
    * `paramiko`
  * if they are not already satisfied

## Known Issues

* some more error checks inside the classes
* some more persons have a look at this
