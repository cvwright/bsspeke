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


def test_knocking(domain, email, token):

    homeserver = "https://matrix." + domain

    test_id = random.getrandbits(24)

    owner_username = "knocking_owner_%06x" % test_id
    owner_userid = "@%s:%s" % (owner_username, domain)
    owner_password = secrets.token_hex(12)
    print("Room owner is [%s]" % owner_userid)

    joiner_username = "knocking_joiner_%06x" % test_id
    joiner_userid = "%s:%s" % (joiner_username, domain)
    joiner_password = secrets.token_hex(12)
    print("Joining user is [%s]" % joiner_userid)

    owner_user_info = {
        "domain": domain,
        "homeserver": homeserver,
        "username": owner_username,
        "user_id": owner_userid,
        "password": owner_password,
        "email": email,
        "registration_token": token,
    }

    joiner_user_info = {
        "domain": domain,
        "homeserver": homeserver,
        "username": joiner_username,
        "user_id": joiner_userid,
        "password": joiner_password,
        "email": email,
        "registration_token": token,
    }

    print("\n\nRegistering room owner as [%s] on Matrix domain [%s]" % (owner_username, domain))
    r = matrix.register(**owner_user_info)
    assert r.status_code == 200
    print("Registration was successful")
    j = r.json()
    owner_access_token = j["access_token"]

    print("\n\nRegistering joining user as [%s] on Matrix domain [%s]" % (joiner_username, domain))
    r = matrix.register(**joiner_user_info)
    assert r.status_code == 200
    print("Registration was successful")
    j = r.json()
    joiner_access_token = j["access_token"]


    createroom_kwargs = {
        "homeserver": homeserver,
        "access_token": owner_access_token,
        "name": "Knock Test %s" % test_id,
        "version": "9",
        "join_rule": "knock"
    }
    print("\n\nCreating room")
    r = matrix.create_room(**createroom_kwargs)
    assert r.status_code == 200
    print("/createRoom call was successful")
    j = r.json()
    room_id = j["room_id"]
    assert room_id != None
    print("Room id is [%s]" % room_id)


    knock_kwargs = {
        "homeserver": homeserver,
        "access_token": joiner_access_token,
        "room_id": room_id,
        "reason": "Test %06x" % test_id,
    }
    print("Knocking on room [%s]" % room_id)
    r = matrix.knock(**knock_kwargs)
    assert r.status_code == 200
    print("/rooms/_/knock call was successful")
    j = r.json()
    assert j["room_id"] == room_id


    invite_kwargs = {
        "homeserver": homeserver,
        "access_token": owner_access_token,
        "room_id": room_id,
        "user_id": joiner_userid,
        "reason": "Test %06x" % test_id,
    }
    print("Inviting to accept the knock")
    r = matrix.invite(**invite_kwargs)
    assert r.status_code == 200
    print("/rooms/_/invite call was successful")


    # Now we need to sync in order to check whether it worked
    joiner_sync_kwargs = {
        "homeserver": homeserver,
        "access_token": joiner_access_token,
    }

    def have_roomid(sync_response):
        rooms = sync_response.get("rooms", None)
        if rooms == None:
            return False
        joined_rooms = rooms.get("join", None)
        if joined_rooms == None:
            return False
        room_info = joined_rooms.get(room_id, None)
        if room_info == None:
            return False
        else:
            return True

    j = matrix.sync_until(have_roomid, **joiner_sync_kwargs)
    assert j != None
