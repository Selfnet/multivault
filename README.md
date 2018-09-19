# multivault

## Python Versions

### Python2

* not supported

### Python3

* 3.5
* 3.6
* 3.7

## Setup normal

* install python3 and python3-pip via your systems packetmanager
* install the package `python-gpgme` also via your systems packetmanager.

* clone this github repository (currently not on pypi)
* install this packet via

  pip install -e .

* or setup python-multivault-git via aur ([Instructions](https://wiki.archlinux.org/index.php/makepkg))

      https://aur.archlinux.org/packages/python-multivault-git/

* your almost there run `multivault --version` <<- if it works, nice!

* config is under `/etc/multivault`
  * if u want to edit this config, copy it to one of the following locations.
    * `/home/$USER/.multivault.yml`
    * `/home/$USER/.config/multivault.yml`
* show loaded config: `multivault --config`

## Description

This is a CLI which connects to a ldap server.
It gathers user information from their to
get the actual admin users for all servers in our organization.

Based on this information it uses the gpg keys of this users
of which the fingerprints are provided by the ldap server itself to encrypt
given passwords or files with the right keys.

Ansible then uses a simple lookup module for the gpg encrypted
files. This is an alpha and not recommended to use in production.

### crypter encrypts and decrypts data via GPG

  apt install python-gpgme gnupg
  pacman -S python-gpgme gnupg
  yum install python-gpgme gnupg

### util_ldap speaks with ldap

#### LDAP3 module

* if u define `ssh_hop` inside the ldap section of
  the config in `multivault.yml` the command is run on
  the local machine and paramiko makes something like

      ssh -L 127.0.0.1:10000:ldap.example.com:636 login_host

* `ldap3` connects than against localhost:10000 and queries the server
* every request opens and closes a tcp connection to the ldap server

## For developers

* Only do this in a virtualenv.

  pip install -e .[dev]

* this installs the development environment of multivault
  * packages like
    * `pylint`
    * `pep8`
    * `autopep8`
  * if they are not already satisfied

