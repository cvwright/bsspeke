#!/bin/env python3

import os
import sys

import base64
import binascii
import json

import BSSpeke

import requests

import random
import secrets

def logged_out_headers():
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

all_capable_stages = [
    "m.login.registration_token",
    "org.futo.subscriptions.free_forever",
    "m.enroll.username",
    "m.login.password",
    "m.login.dummy",
    "m.enroll.password",
    "m.login.terms",
    "m.login.bsspeke-ecc.oprf",
    "m.login.bsspeke-ecc.verify",
    "m.enroll.bsspeke-ecc.oprf",
    "m.enroll.bsspeke-ecc.save",
    "m.enroll.email.request_token",
    "m.enroll.email.submit_token",
    "m.login.email.request_token",
    "m.login.email.submit_token",
]

session_storage = {}


def do_generic_uia_stage(*args, **kwargs):
    (func, url, headers, body) = args
    auth = kwargs["auth"]
    uia_body = body.copy()
    uia_body["auth"] = auth
    print("Doing UIA stage with request body =", json.dumps(uia_body, indent=4))
    response = func(url, headers=headers, json=uia_body)
    if response.status_code not in [200,401]:
        try:
            j = response.json()
            error = j["error"]
            errcode = j["errcode"]
            print("UIA got an error: %s %s" % (errcode, error))
        except:
            print("UIA got an error response (HTTP %d)" % response.status_code)
    return response


def do_m_login_registration_token(*args, **kwargs):
    token = kwargs["token"]
    session = kwargs["session"]
    auth = {
        "type": "m.login.registration_token",
        "session": session,
        "token": token,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_org_futo_subscriptions_free_forever(*args, **kwargs):
    session = kwargs["session"]
    auth = {
        "type": "org.futo.subscriptions.free_forever",
        "session": session,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_enroll_username(*args, **kwargs):
    username = kwargs["username"]
    session = kwargs["session"]
    auth = {
        "type": "m.enroll.username",
        "session": session,
        "username": username,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_login_terms(*args, **kwargs):
    session = kwargs["session"]
    auth = {
        "type": "m.login.terms",
        "session": session,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_enroll_password(*args, **kwargs):
    password = kwargs["new_password"]
    session = kwargs["session"]
    auth = {
        "type": "m.enroll.password",
        "session": session,
        "password": password,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_login_password(*args, **kwargs):
    password = kwargs["password"]
    session = kwargs["session"]
    auth = {
        "type": "m.login.password",
        "session": session,
        "password": password,
    }
    return do_generic_uia_stage(*args, auth=auth)

def do_m_login_dummy(*args, **kwargs):
    session = kwargs["session"]
    auth = {
        "type": "m.login.dummy",
        "session": session,
    }
    return do_generic_uia_stage(*args, auth=auth)

def do_m_enroll_email_request_token(*args, **kwargs):
    email = kwargs["email"]
    session = kwargs["session"]
    auth = {
        "type": "m.enroll.email.request_token",
        "session": session,
        "email": email,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_enroll_email_submit_token(*args, **kwargs):
    token = kwargs["token"]
    session = kwargs["session"]
    auth = {
        "type": "m.enroll.email.submit_token",
        "session": session,
        "token": token,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_login_email_request_token(*args, **kwargs):
    email = kwargs["email"]
    session = kwargs["session"]
    auth = {
        "type": "m.login.email.request_token",
        "session": session,
        "email": email,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_login_email_submit_token(*args, **kwargs):
    token = kwargs["token"]
    session = kwargs["session"]
    auth = {
        "type": "m.login.email.submit_token",
        "session": session,
        "token": token,
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_enroll_bsspeke_oprf(*args, **kwargs):
    domain = kwargs["domain"]
    user_id = kwargs["user_id"]
    password = kwargs.get("new_password", None) or kwargs["password"]
    session = kwargs["session"]

    client = BSSpeke.Client(user_id, domain, password)
    curve = "curve25519"
    blind = client.generate_blind()
    blind_base64 = binascii.b2a_base64(blind, newline=False).decode('utf-8')

    session_storage[session] = {
        "client": client
    }

    auth = {
        "type": "m.enroll.bsspeke-ecc.oprf",
        "curve": curve,
        "blind": blind_base64,
        "session": session
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_enroll_bsspeke_save(*args, **kwargs):
    session = kwargs["session"]
    client = session_storage[session]["client"]
    
    uia_state = kwargs["state"]
    save_params = uia_state["params"]["m.enroll.bsspeke-ecc.save"]
    blind_salt = save_params["blind_salt"]
    phf_params = {
        "name": "argon2i",
        "iterations": 3,
        "blocks": 100000
    }
    P,V = client.generate_P_and_V(base64.b64decode(blind_salt), phf_params)
    
    auth = {
        "type": "m.enroll.bsspeke-ecc.save",
        "P": binascii.b2a_base64(P, newline=False).decode('utf-8'),
        "V": binascii.b2a_base64(V, newline=False).decode('utf-8'),
        "phf_params": phf_params,
        "session": session
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_login_bsspeke_oprf(*args, **kwargs):
    domain = kwargs["domain"]
    user_id = kwargs["user_id"]
    password = kwargs["password"]
    session = kwargs["session"]

    client = BSSpeke.Client(user_id, domain, password)
    curve = "curve25519"
    blind = client.generate_blind()
    blind_base64 = binascii.b2a_base64(blind, newline=False).decode('utf-8')

    session_storage[session] = {
        "client": client
    }

    auth = {
        "type": "m.login.bsspeke-ecc.oprf",
        "curve": curve,
        "blind": blind_base64,
        "session": session
    }
    return do_generic_uia_stage(*args, auth=auth)


def do_m_login_bsspeke_verify(*args, **kwargs):
    session = kwargs["session"]
    state = kwargs["state"]

    oprf_params = state["params"]["m.login.bsspeke-ecc.oprf"]
    phf_params = oprf_params["phf_params"]

    verify_params = state["params"]["m.login.bsspeke-ecc.verify"]

    blind_salt_str = verify_params["blind_salt"]
    B_str = verify_params["B"]
    blind_salt = base64.b64decode(blind_salt_str)
    B = base64.b64decode(B_str)

    client = session_storage[session]["client"]

    A_bytes = client.generate_A(blind_salt, phf_params)
    client.derive_shared_key(B)
    verifier_bytes = client.generate_verifier()

    A = binascii.b2a_base64(A_bytes, newline=False).decode('utf-8')
    verifier = binascii.b2a_base64(verifier_bytes, newline=False).decode('utf-8')

    auth = {
        "type": "m.login.bsspeke-ecc.verify",
        "A": A,
        "verifier": verifier,
        "session": session
    }
    return do_generic_uia_stage(*args, auth=auth)




def do_uia_stage(*args, **kwargs):
    stage = kwargs["stage"]
    state = kwargs["state"]
    session = state["session"]

    print("Doing UIA stage [%s]" % stage)

    if stage == "m.enroll.username":
        username = kwargs["username"]
        return do_m_enroll_username(*args, session=session, username=username)

    elif stage == "m.enroll.password":
        password = kwargs["password"]
        return do_m_enroll_password(*args, session=session, password=password)

    elif stage == "m.login.password":
        password = kwargs["password"]
        return do_m_login_password(*args, session=session, password=password)

    elif stage == "m.login.dummy":
        return do_m_login_dummy(*args, session=session)

    elif stage == "m.login.terms":
        return do_m_login_terms(*args, session=session)

    elif stage == "m.login.registration_token":
        token = kwargs["registration_token"]
        return do_m_login_registration_token(*args, session=session, token=token)

    elif stage == "org.futo.subscriptions.free_forever":
        return do_org_futo_subscriptions_free_forever(*args, session=session)

    elif stage == "m.login.bsspeke-ecc.oprf":
        domain = kwargs["domain"]
        user_id = kwargs["user_id"]
        password = kwargs["password"]
        return do_m_login_bsspeke_oprf(*args, session=session, domain=domain, user_id=user_id, password=password)

    elif stage == "m.enroll.bsspeke-ecc.oprf":
        domain = kwargs["domain"]
        user_id = kwargs["user_id"]
        password = kwargs["new_password"]
        return do_m_enroll_bsspeke_oprf(*args, session=session, domain=domain, user_id=user_id, password=password)

    elif stage == "m.enroll.bsspeke-ecc.save":
        state = kwargs["state"]
        return do_m_enroll_bsspeke_save(*args, session=session, state=state)

    elif stage == "m.login.bsspeke-ecc.oprf":
        domain = kwargs["domain"]
        user_id = kwargs["user_id"]
        password = kwargs["password"]
        return do_m_login_bsspeke_oprf(*args, session=session, domain=domain, user_id=user_id, password=password)

    elif stage == "m.login.bsspeke-ecc.verify":
        state = kwargs["state"]
        return do_m_login_bsspeke_verify(*args, session=session, state=state)

    elif stage == "m.enroll.email.request_token":
        email = kwargs["email"]
        return do_m_enroll_email_request_token(*args, session=session, email=email)
    elif stage == "m.enroll.email.submit_token":
        token = input("Enter email token: ")
        return do_m_enroll_email_submit_token(*args, session=session, token=token)

    elif stage == "m.login.email.request_token":
        email = kwargs["email"]
        return do_m_login_email_request_token(*args, session=session, email=email)
    elif stage == "m.login.email.submit_token":
        token = input("Enter email token: ")
        return do_m_login_email_submit_token(*args, session=session, token=token)

    assert False # Throw an error if we are still here


def do_uia_request(func, url, headers, body, **kwargs):
    print("Doing UIA request for URL [%s]" % url)
    # First submit the request with no `auth` object
    # If we get a 401, then we need to complete the UIA process
    # Otherwise the request seems to have gone through

    r = func(url, headers=headers, json=body)
    print("Got initial response:")
    try:
        j = r.json()
        print(json.dumps(j, indent=4))
    except:
        print(r.text)

    selected_flow = None
    while r.status_code == 401:
        print("\n\nWorking on UIA\n")
        uia_state = r.json()
        flows = uia_state.get("flows", [])
        print("Got flows =", json.dumps(flows, indent=4))
        completed = uia_state.get("completed", [])
        print("Got completed =", completed)

        capable_stages = kwargs.get("stages", all_capable_stages)

        # Which flow are we working towards completing?
        if selected_flow is None:
            for flow in flows:
                stages = flow.get("stages", [])
                if set(stages) <= set(capable_stages):
                    selected_flow = flow
                    break
        assert selected_flow != None

        # Which stage should we complete next?
        flow_stages = selected_flow.get("stages", [])
        print("Flow stages =", flow_stages)
        tbd_stages = [stage for stage in flow_stages if stage not in completed]
        print("TBD stages =", tbd_stages)
        next_stage = tbd_stages[0]

        # Attempt the stage and see what we get
        # kwargs should contain everything that we might need (user_id, password, email address, server domain, ...)
        kwargs["session"] = uia_state["session"]
        kwargs["stage"] = next_stage
        kwargs["state"] = uia_state
        r = do_uia_stage(func, url, headers, body, **kwargs)

    return r

def register(**kwargs):
    homeserver = kwargs["homeserver"]
    domain = kwargs["domain"]
    user_id = kwargs["user_id"]
    username = kwargs["username"]
    password = kwargs["new_password"]
    inhibit_login = kwargs.get("inhibit_login", False)
    refresh_token = kwargs.get("refresh_token", False)
    print("Registering user [%s] on domain [%s] with password [%s]" % (user_id, domain, password))
    #email = kwargs["email"]
    #registration_token = kwargs["registration_token"]
    path = "/_matrix/client/v3/register"
    url = homeserver + path
    body = {
        "username": username,
        "password": password,
        "inhibit_login": inhibit_login,
        "refresh_token": refresh_token,
    }
    r = do_uia_request(requests.post, url, logged_out_headers(), body, **kwargs)
    return r


def login(**kwargs):
    domain = kwargs["domain"]
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    password = kwargs.get("password", None)
    enable_refresh_token = kwargs.get("refresh_token", False)
    print("Logging in user [%s] on domain [%s] with password [%s]" % (user_id, domain, password))
    path = "/_matrix/client/v3/login"
    url = homeserver + path
    login_body = {  
        "identifier": {
            "type": "m.id.user",
            "user": user_id,
        }
    }
    for key in ["device_id", "initial_device_display_name", "refresh_token"]:
        if key in kwargs:
            login_body[key] = kwargs[key]
    if enable_refresh_token:
        login_body["refresh_token"] = True

    # Make sure that we're not trying to log in from an already logged-in session
    assert "access_token" not in kwargs

    r = do_uia_request(requests.post, url, logged_out_headers(), login_body, **kwargs)
    return r


def get_devices(**kwargs):
    access_token = kwargs["access_token"]
    homeserver = kwargs["homeserver"]
    path = "/_matrix/client/v3/devices"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    get_devices_body = {
    }
    r = requests.get(url, headers=headers, json=get_devices_body)
    #return r
    assert r.status_code == 200

    j = r.json()
    assert "devices" in j

    return j["devices"]


def whoami(**kwargs):
    access_token = kwargs["access_token"]
    print("\nAsking 'Who am I?' with access_token [%s]" % access_token)

    homeserver = kwargs["homeserver"]
    path = "/_matrix/client/v3/account/whoami"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    whoami_body = {
    }
    r = requests.get(url, headers=headers, json=whoami_body)
    #return r
    assert r.status_code == 200

    j = r.json()
    assert "user_id" in j

    return j["user_id"]


def deactivate(**kwargs):
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    access_token = kwargs["access_token"]

    print("\n\n")
    print("*" * 60)
    print("Deactivating account for user [%s]" % user_id)

    path = "/_matrix/client/v3/account/deactivate"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    deactivate_body = {
    }
    r = do_uia_request(requests.post, url, headers, deactivate_body, **kwargs)
    return r


# https://spec.matrix.org/v1.4/client-server-api/#delete_matrixclientv3devicesdeviceid
def delete_device(device_id, **kwargs):
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    access_token = kwargs["access_token"]

    print("\n\n")
    print("*" * 60)
    print("Deleting device [%s] for user [%s]" % (device_id, user_id))

    path = "/_matrix/client/v3/devices/%s" % device_id
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    delete_device_body = {
    }
    r = do_uia_request(requests.delete, url, headers, delete_device_body, **kwargs)
    return r

# https://spec.matrix.org/v1.4/client-server-api/#post_matrixclientv3delete_devices
def delete_devices(devices, **kwargs):
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    access_token = kwargs["access_token"]

    print("\n\n")
    print("*" * 60)
    print("Deleting devices for user [%s]" % user_id)

    path = "/_matrix/client/v3/delete_devices"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    delete_devices_body = {
        "devices": devices
    }
    r = do_uia_request(requests.post, url, headers, delete_devices_body, **kwargs)
    return r


def account_auth(**kwargs):
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    access_token = kwargs["access_token"]

    print("\n\n")
    print("*" * 60)
    print("Changing password for user [%s]" % user_id)

    path = "/_matrix/client/v3/account/auth"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    account_auth_body = {
    }
    r = do_uia_request(requests.post, url, headers, account_auth_body, **kwargs)
    return r


def create_room(**kwargs):
    # Non-optional kwargs
    homeserver = kwargs.get("homeserver", None)
    if homeserver is None:
        domain = kwargs.get("domain", None)
        assert domain is not None
        homeserver = "https://matrix.%s/" % domain
    access_token = kwargs["access_token"]

    # Optional kwargs
    name = kwargs.get("name", None)
    room_type = kwargs.get("type", None)
    topic = kwargs.get("topic", None)
    preset = kwargs.get("preset", "private_chat")
    join_rule = kwargs.get("join_rule", "invite")
    version = kwargs.get("room_version", None)

    print("\n\n")
    print("*" * 60)
    print("Creating room")

    path = "/_matrix/client/v3/createRoom"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    create_body = {}
    if name is not None:
        create_body["name"] = name
    if room_type is not None:
        create_body["type"] = room_type
    if topic is not None:
        create_body["topic"] = topic
    if preset is not None:
        create_body["preset"] = preset
    if version is not None:
        create_body["room_version"] = version
    if join_rule is not None:
        create_body["initial_state"] = [
            {
                "type": "m.room.join_rules",
                "content": {
                    "join_rule": join_rule
                }
            }
        ]

    r = requests.post(url, headers=headers, json=create_body)
    #if r.status_code == 200:
    #    j = r.json()
    #    return j["room_id"]
    #else:
    #    j = r.json()
    #    errcode = j.get("errcode", "???")
    #    error = j.get("error", "unknown")
    #    print("Matrix error: %s - %s" % (errcode, error))
    #    return None
    return r


def knock(**kwargs):
    # Non-optional kwargs
    homeserver = kwargs["homeserver"]
    access_token = kwargs["access_token"]
    room_id = kwargs["room_id"]

    # Optional kwargs
    reason = kwargs.get("reason", None)

    #print("\n\n")
    #print("*" * 60)
    #print("Knocking on room %s" % room_id)

    path = "/_matrix/client/v3/knock/%s" % room_id
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    knock_body = {
        "reason": reason
    }

    r = requests.post(url, headers=headers, json=knock_body)
    #assert r.status_code == 200
    #j = r.json()
    #return j["room_id"]
    return r

def join(**kwargs):
    # Non-optional kwargs
    homeserver = kwargs["homeserver"]
    access_token = kwargs["access_token"]
    room_id = kwargs["room_id"]

    # Optional kwargs
    reason = kwargs.get("reason", None)

    #print("\n\n")
    #print("*" * 60)
    #print("Joining room %s" % room_id)

    path = "/_matrix/client/v3/join/%s" % room_id
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    join_body = {
        "reason": reason
    }

    r = requests.post(url, headers=headers, json=join_body)
    #assert r.status_code == 200
    #j = r.json()
    #return j["room_id"]
    return r


def invite(**kwargs):
    # Non-optional kwargs
    homeserver = kwargs["homeserver"]
    access_token = kwargs["access_token"]
    room_id = kwargs["room_id"]
    user_id = kwargs["user_id"]

    # Optional kwargs
    reason = kwargs.get("reason", None)

    #print("\n\n")
    #print("*" * 60)
    #print("Inviting user %s to room %s" % (user_id, room_id))

    path = "/_matrix/client/v3/rooms/%s/invite" % room_id
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    invite_body = {
        "user_id": user_id,
        "reason": reason,
    }

    r = requests.post(url, headers=headers, json=invite_body)
    #assert r.status_code == 200
    return r


def sync(**kwargs):
    homeserver = kwargs["homeserver"]
    access_token = kwargs["access_token"]

    sync_token = kwargs.get("sync_token", None)
    timeout = kwargs.get("sync_timeout", 30000)
    full_state = kwargs.get("full_state", None)

    path = "/_matrix/client/v3/sync?timeout=%s" % timeout
    if sync_token is not None:
        path += "&since=%s" % sync_token
    if full_state is not None and full_state is True:
        path += "&full_state=true"
    url = homeserver + path

    headers = logged_out_headers()
    headers["Authorization"] = "Bearer %s" % access_token

    print("Syncing with access token [%s]" % access_token)
    r = requests.get(url, headers=headers)
    assert r.status_code == 200

    return r.json()


# Call /sync until the function returns True
def sync_until(func, **kwargs):

    homeserver = kwargs["homeserver"]
    access_token = kwargs["access_token"]
    max_tries = kwargs.get("max_tries", 10)
    full_state = kwargs.get("full_state", False)

    sync_token = None
    tries = 0
    while True:
        json_response = sync(homeserver=homeserver, access_token=access_token, sync_token=sync_token, full_state=full_state)
        tries += 1
        print("Testing /sync response")
        if func(json_response) == True:
            return json_response
        elif tries >= max_tries:
            return None
        else:
            sync_token = json_response["next_batch"]


