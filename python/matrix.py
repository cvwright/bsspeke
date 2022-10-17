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

logged_out_headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

capable_stages = [
    "m.login.registration_token",
    "m.enroll.username",
    "m.login.password",
    "m.enroll.password",
    "m.login.terms",
    "m.login.bsspeke-ecc.oprf",
    "m.login.bsspeke-ecc.verify",
    "m.enroll.bsspeke-ecc.oprf",
    "m.enroll.bsspeke-ecc.save",
    "m.enroll.email.request_token",
    "m.enroll.email.submit_token",
]

session_storage = {}


def do_generic_uia_stage(*args, **kwargs):
    (func, url, headers, body) = args
    auth = kwargs["auth"]
    json = body.copy()
    json["auth"] = auth
    return func(url, headers=headers, json=json)


def do_m_login_registration_token(*args, **kwargs):
    token = kwargs["token"]
    session = kwargs["session"]
    auth = {
        "type": "m.login.registration_token",
        "session": session,
        "token": token,
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
    password = kwargs["password"]
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


def do_m_enroll_bsspeke_oprf(*args, **kwargs):
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

    elif stage == "m.login.terms":
        return do_m_login_terms(*args, session=session)

    elif stage == "m.login.registration_token":
        token = kwargs["registration_token"]
        return do_m_login_registration_token(*args, session=session, token=token)

    elif stage == "m.login.bsspeke-ecc.oprf":
        domain = kwargs["domain"]
        user_id = kwargs["user_id"]
        password = kwargs["password"]
        return do_m_login_bsspeke_oprf(*args, session=session, domain=domain, user_id=user_id, password=password)

    elif stage == "m.enroll.bsspeke-ecc.oprf":
        domain = kwargs["domain"]
        user_id = kwargs["user_id"]
        password = kwargs["password"]
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

    assert False # Throw an error if we are still here


def do_uia_request(func, url, headers, body, **kwargs):
    print("Doing UIA request for URL [%s]" % url)
    # First submit the request with no `auth` object
    # If we get a 401, then we need to complete the UIA process
    # Otherwise the request seems to have gone through

    r = func(url, headers=headers, json=body)
    selected_flow = None
    while r.status_code == 401:
        print("\n\nWorking on UIA\n")
        uia_state = r.json()
        flows = uia_state.get("flows", [])
        print("Got flows =", json.dumps(flows, indent=4))
        completed = uia_state.get("completed", [])
        print("Got completed =", completed)

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
    password = kwargs["password"]
    print("Registering user [%s] on domain [%s] with password [%s]" % (user_id, domain, password))
    #email = kwargs["email"]
    #registration_token = kwargs["registration_token"]
    path = "/_matrix/client/v3/register"
    url = homeserver + path
    r = do_uia_request(requests.post, url, logged_out_headers, {}, **kwargs)
    return r


def login(**kwargs):
    domain = kwargs["domain"]
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    password = kwargs["password"]
    print("Logging in user [%s] on domain [%s] with password [%s]" % (user_id, domain, password))
    path = "/_matrix/client/v3/login"
    url = homeserver + path
    login_body = {  
        "identifier": {
            "type": "m.id.user",
            "user": user_id,
        }
    }
    r = do_uia_request(requests.post, url, logged_out_headers, login_body, **kwargs)
    return r


def whoami(**kwargs):
    access_token = kwargs["access_token"]
    print("\nAsking 'Who am I?' with access_token [%s]" % access_token)

    homeserver = kwargs["homeserver"]
    path = "/_matrix/client/v3/account/whoami"
    url = homeserver + path

    headers = logged_out_headers
    headers["Authorization"] = "Bearer %s" % access_token

    whoami_body = {
    }
    r = requests.get(url, headers=headers, json=whoami_body)
    return r


def deactivate(**kwargs):
    homeserver = kwargs["homeserver"]
    user_id = kwargs["user_id"]
    access_token = kwargs["access_token"]

    print("\n\n")
    print("*" * 60)
    print("Deactivating account for user [%s]" % user_id)

    path = "/_matrix/client/v3/account/deactivate"
    url = homeserver + path

    headers = logged_out_headers
    headers["Authorization"] = "Bearer %s" % access_token

    deactivate_body = {
    }
    r = do_uia_request(requests.post, url, headers, deactivate_body, **kwargs)
    return r

