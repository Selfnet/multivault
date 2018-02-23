# This folder contains the python classes for multivault

This is only supported via python3 at the moment

## Setup normal

* install python3 via your packet manager

      pip install .

* to install the ansible_multivault package to your path.
* your almost there run `ansible-multivault --version` <<- if it works, nice!
* config is under `~/.config/.multivault.yml`

## Setup development

    pip install -e .[dev]

## crypter encrypts and decrypts data via GPG

* requires
  * gpg or gpg2   <-- for decryption and encryption via GPG
  * install gnupg | gnupg2 for that purpose with your preferred packet manager

## util_ldap speaks with ldap

### LDAP3 module

* to use ldap3 install with `ldap3` environment

      pip install -e .[ldap3]

* if u define `ssh_hop` inside the ldap section of
  the config `.multivault.yml` the command is run on
  the local machine and paramiko makes something like

      ssh -L 127.0.0.1:10000:ldap.example.com:636 login_host

* `ldap3` connects than against localhost:10000 and queries the server
* every request opens and closes a tcp connection to the ldap server

### LDAPSEARCH command line wrapper

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
