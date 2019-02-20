#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import re
import sys

import click
import ldap3
from ldap3 import Server, Connection, ALL

CONFIG_FILE_LOCATION = './config.json'

log = logging.getLogger(__file__)
cfg = {}


def _configure_logging(verbosity):
    loglevel = max(3 - verbosity, 0) * 10
    logging.basicConfig(level=loglevel, format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    if loglevel >= logging.DEBUG:
        # Disable debugging logging for external libraries
        for loggername in 'urllib3', 'google.auth.transport.requests':
            logging.getLogger(loggername).setLevel(logging.CRITICAL)


def get_config(file_path: str):
    config = {}
    with open(file_path, 'r') as f:
        loaded_config = json.load(f)
        config.update(loaded_config)
    return config


def search_ldap(cfg: dict):
    attributes = [cfg['attributes'][k] for k in cfg['attributes'].keys() if cfg['attributes'][k]]

    if cfg['userobjectfilter']:
        search_filter = "(&(objectclass={})({}))".format(cfg['objectclass'], cfg['userobjectfilter'])
    else:
        search_filter = "(objectclass={})".format(cfg['objectclass'])

    server = Server(cfg['server'], port=cfg['port'], get_info=ALL)
    conn = Connection(server, cfg['binddn'], cfg['secret'], auto_bind=True)
    conn.search(
        search_base=",".join([cfg['usersearchbase'], cfg['basedn']]),
        search_filter=search_filter,
        attributes=attributes)

    return [json.loads(e.entry_to_json())['attributes'] for e in conn.entries]


def remap_ldap_attributes(cfg: dict, user: dict):
    remapped = {}
    for attr in cfg['attributes'].keys():
        remapped[attr] = user[cfg['attributes'][attr]] if cfg['attributes'][attr] in user else ""

    return remapped


def _save_user_keys(user: dict, base_path: str, keys_file: str):
    if not re.match(cfg['validuserregex'], user['uid'][0]):
        raise ValueError()

    userpath = os.path.join(base_path, user['uid'][0])
    auth_keys_file = os.path.join(userpath, keys_file)
    log.debug(userpath)

    # Create users directory and ensure ownership and permissions
    if not os.path.isdir(userpath):
        os.mkdir(userpath)
        log.debug("Adding user %s", user['uid'][0])
    os.chmod(userpath, 0o700)
    os.chown(userpath, uid=user['uidNumber'][0], gid=user['gidNumber'][0])

    # Create authorized_keys file and ensure ownership and permissions
    with open(auth_keys_file, "w") as f:
        f.writelines(user['sshkeys'])
        log.debug("Wrote %d keys for %s", len(user['sshkeys']), user['uid'][0])
    os.chmod(auth_keys_file, 0o600)
    os.chown(auth_keys_file, uid=user['uidNumber'][0], gid=user['gidNumber'][0])


@click.group()
@click.option('-c', '--cfg-path', help='Configuration file', default=CONFIG_FILE_LOCATION, type=str)
@click.option('-v', '--verbosity', help='Verbosity', default=0, count=True)
def cli(verbosity: int, cfg_path: str):
    """ main program
    """
    global cfg

    _configure_logging(verbosity)
    cfg = get_config(cfg_path)

    return 0


@cli.command(name='list-keys')
def list_keys():
    print(json.dumps(search_ldap(cfg), indent=2, sort_keys=True))


@cli.command(name='update-keys')
@click.option('-a', '--authorized-keys-filename', help='name of the users authorized_keys file', type=str)
@click.option('-k', '--key-base-path', help='where to put the keys', type=str)
@click.option('-d', '--delete', help='delete user keys for users not longer in ldap', is_flag=True)
@click.option('-m', '--create-output-dir', help='create output path if not exists', is_flag=True)
def update_keys(authorized_keys_filename: str, key_base_path: str, create_output_dir: bool, delete: bool):
    if not authorized_keys_filename:
        authorized_keys_filename = cfg['authorized_keys_filename']
    if not key_base_path:
        key_base_path = cfg['key_base_path']

    if create_output_dir and not os.path.isdir(key_base_path):
        os.makedirs(key_base_path)

    # get userinfo and create keys files
    users = [remap_ldap_attributes(cfg, u) for u in search_ldap(cfg)]
    for user in users:
        try:
            _save_user_keys(user, key_base_path, authorized_keys_filename)
        except ValueError:
            log.warning("Skipped %s due to invalid username", user['uid'][0])

    logging.info("Processed %d uids from ldap", len(users))

    # Clean up old directories whose uid is not found in ldap any longer
    if delete:
        uids = [u['uid'][0] for u in users]
        deleted_users = [u for u in next(os.walk(key_base_path))[1] if u not in uids]

        log.debug('Removing users: %s', deleted_users)
        for uid in deleted_users:
            userpath = os.path.join(key_base_path, uid)
            os.remove(os.path.join(userpath, authorized_keys_filename))
            os.rmdir(userpath)

        logging.info("Removed %d users", len(deleted_users))


if __name__ == '__main__':
    sys.exit(cli())
