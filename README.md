# multivault prior to use with ansible

This is only supported via python3 at the moment

## Setup normal

* install python3 and python3-pip via your packet manager
* then install the package

      make install

* or setup python-multivault-git via aur ([Instructions](https://wiki.archlinux.org/index.php/makepkg))

      https://aur.archlinux.org/packages/python-multivault-git/

* your almost there run `multivault --version` <<- if it works, nice!
* config is under `/etc/multivault`
  * if u want to edit this config, create it under
    * `/home/$USER/.multivault.yml`
    * `/home/$USER/.config/multivault.yml`
* show loaded config: `multivault --config`

## Setup development

    make dev

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
  the server specified by the hostname. So you not need ldapsearch to be installed.
  To get this to work, you must have login access to this server. SSH_CONFIG is also used
  by this method.

## For developers

* Only do this in a virtualenv.

    pip install -e .[dev]

    make dev

* this installs the development environment of multivault
  * packages like
    * `pylint`
    * `pep8`
    * `autopep8`
  * if they are not already satisfied

## Known Issues

* some more error checks inside the classes
* some more persons have a look at this
