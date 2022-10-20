#!/bin/env python3

import os
import sys
import copy
import time

import base64
import binascii
import json

import BSSpeke

import requests

import random
import secrets

import matrix


def test_register_login_deactivate(domain):
    homeserver = "https://matrix." + domain

    username = "test_%04x" % random.getrandbits(16)
    user_id = "@%s:%s" % (username, domain)
    password = secrets.token_hex(12)
    email = "%s@example.com" % username
    print("Running test with user id [%s]" % user_id)

    user_info = {
        "domain": domain,
        "homeserver": homeserver,
        "username": username,
        "user_id": user_id,
        "password": password,
        "email": email,
        "registration_token": "0000-1111-2222-4444",
    }

    print("\n\nRegistering username [%s] on Matrix domain [%s]" % (username, domain))
    r1 = matrix.register(**user_info)
    assert r1.status_code == 200
    print("Registration was successful")

    print("\n\nLogging in as Matrix user [%s]" % user_id)
    device_display_name = "Test Device " + secrets.token_hex(4)
    user_info["initial_device_display_name"] = device_display_name
    r2 = matrix.login(**user_info)
    assert r2.status_code == 200
    j2 = r2.json()
    access_token = j2.get("access_token", None)
    assert access_token != None
    user_info["access_token"] = access_token
    device_id = j2.get("device_id", None)
    print("Logged in as [%s] with access token [%s] and device id [%s]" % (user_id, access_token, device_id))

    # Check whether the server used our initial device display name
    print("Checking devices...")
    devices = matrix.get_devices(**user_info)
    found = False
    for device in devices:
        this_device_id = device.get("device_id", None)
        this_device_name = device.get("display_name", None)
        print("\tFound device %s with display name \"%s\"" % (this_device_id, this_device_name))
        if this_device_id == device_id:
            found = True
            assert this_device_name == device_display_name
    assert found == True
    

    print("\n\nQuerying /whoami on homeserver [%s]" % homeserver)
    whoami_userid = matrix.whoami(**user_info)
    print("Server says I am [%s]" % whoami_userid)
    assert whoami_userid == user_id

    for i in range(10,0,-1):
        time.sleep(1)
        print("%d" % i)
    print("\n\nLogging in a 2nd session")
    copy_info = user_info.copy()
    del copy_info["access_token"]
    #del copy_info["device_id"]
    r = matrix.login(**copy_info)
    print("Got /login response ", r)
    assert r.status_code == 200
    j = r.json()
    access_token_2 = j.get("access_token", None)
    device_id_2 = j.get("device_id", None)
    assert access_token_2 != None
    assert device_id_2 != None

    print("\n\nDeleting 2nd device")
    #r = matrix.delete_devices([device_id_2], **user_info)
    r = matrix.delete_device(device_id_2, **user_info)
    assert r.status_code == 200
    print("Successfully deleted devices")

    print("\n\nChanging BS-SPEKE password")
    new_password = secrets.token_hex(12)
    user_info["new_password"] = new_password
    r = matrix.account_auth(**user_info)
    assert r.status_code == 200
    print("Successfully changed BS-SPEKE password")

    print("\n\nDeactivating account on homeserver [%s]" % homeserver)
    r3 = matrix.deactivate(**user_info)
    assert r3.status_code == 200
    print("Deactivation was successful")


if __name__ == "__main__":
    domain = sys.argv[1]
    test_register_login_deactivate(domain)
