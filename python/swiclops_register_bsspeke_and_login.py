#!/bin/env python3

import sys
import base64
import binascii
import json
import requests
import random
import secrets

import BSSpeke

def register(server, username, password, email):

    path = "/_matrix/client/v3/register"
    url = server + path

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Request 1: Empty #####################################################
    print("\n\nRequest 1: New session\n")
    r1 = requests.post(url, headers=headers, json={})
    print("Got status: %d" % r1.status_code)
    j1 = r1.json()
    session_id = j1.get("session", None)
    print("Got session id = [%s]" % session_id)
    flows = j1.get("flows", None)
    print("Got flows:")
    uia_stages = None
    for flow in flows:
        stages = flow.get("stages", [])
        print("\t", stages)
        if uia_stages is None:
            uia_stages = stages
    print("Got response: ", json.dumps(j1, indent=4))

    # Request 2: Registration token ########################################
    print("\n\nRequest 2: Registration token\n")
    body = {
        "auth": {
            "type": "m.login.registration_token",
            "token": "0000-1111-2222-4444",
            "session": session_id
        }
    }
    r2 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r2.status_code)
    j2 = r2.json()
    completed = j2.get("completed", [])
    print("Got completed stages: ", completed)
    print("Got response: ", json.dumps(j2, indent=2))

    # Request 3: Terms of service ##########################################
    print("\n\nRequest 3: Terms of service\n")
    body = {
        "auth": {
            "type": "m.login.terms",
            "session": session_id
        }
    }
    r3 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r3.status_code)
    j3 = r3.json()
    completed = j3.get("completed", [])
    print("Got completed stages: ", completed)
    print("Got response: ", json.dumps(j3, indent=4))

    # Request 4: Terms of service ##########################################
    print("\n\nRequest 4: Claim username\n")
    body = {
        "auth": {
            "type": "m.enroll.username",
            "session": session_id,
            "username": username
        }
    }
    r4 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r4.status_code)
    j4 = r4.json()
    completed = j4.get("completed", [])
    print("Got completed stages: ", completed)
    print("Got response: ", json.dumps(j4, indent=4))



    require_email = True
    if require_email:

        # Request 5: Request email token #######################################
        print("\n\nRequest 5: Request email token\n")
        body = {
            "auth": {
                "type": "m.enroll.email.request_token",
                "email": email,
                "session": session_id
            }
        }
        r5 = requests.post(url, headers=headers, json=body)
        print("Got status: %d" % r5.status_code)
        completed = r5.json().get("completed", [])
        print("Got completed stages: ", completed)

        # Request 6: Submit email token #######################################
        email_token = input("Enter email token: ")
        print("\n\nRequest 6: Submit email token\n")
        body = {
            "auth": {
                "type": "m.enroll.email.submit_token",
                "token": email_token,
                "session": session_id
            }
        }
        r6 = requests.post(url, headers=headers, json=body)
        print("Got status: %d" % r6.status_code)
        completed = r6.json().get("completed", [])
        print("Got completed stages: ", completed)

    # Request 7: BS-SPEKE OPRF
    print("\n\nRequest 7: BS-SPEKE OPRF\n")
    client = BSSpeke.Client(user_id, domain, password)
    client_id = client.get_client_id()
    blind = client.generate_blind()
    print("Got client_id = [%s]" % client_id)
    print("Got blind = [%s]" % str(blind))

    oprf_params = j1["params"]["m.enroll.bsspeke-ecc.oprf"]
    curve = oprf_params["curve"]
    blind_base64 = binascii.b2a_base64(blind, newline=False).decode('utf-8')
    print("Blind (base64) = [%s]" % blind_base64)

    body = {
        "auth": {
            "type": "m.enroll.bsspeke-ecc.oprf",
            "curve": curve,
            "blind": blind_base64,
            "session": session_id
        }
    }
    r7 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r6.status_code)
    j7 = r7.json()
    print("Got response: ", json.dumps(j7, indent=4))
    completed = j7.get("completed", [])
    print("Got completed stages: ", completed)
    r7_params = j7.get("params", {})
    print("Got params: ", json.dumps(r7_params))
    if r7.status_code != 401:
        error = j7.get("error", "???")
        errcode = j7.get("errcode", "???")
        print("Got error response: %s %s" % (errcode, error))

    # Request 8: BS-SPEKE Save 
    print("\n\nRequest 8: BS-SPEKE OPRF\n")
    save_params = j7["params"]["m.enroll.bsspeke-ecc.save"]
    blind_salt = save_params["blind_salt"]
    phf_params = {
        "name": "argon2i",
        "iterations": 3,
        "blocks": 100000
    }
    P,V = client.generate_P_and_V(base64.b64decode(blind_salt), phf_params)

    body = {
        "auth": {
            "type": "m.enroll.bsspeke-ecc.save",
            "P": binascii.b2a_base64(P, newline=False).decode('utf-8'),
            "V": binascii.b2a_base64(V, newline=False).decode('utf-8'),
            "phf_params": phf_params,
            "session": session_id
        }
    }
    r8 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r8.status_code)
    j8 = r8.json()
    completed = j8.get("completed", [])
    print("Got completed stages: ", completed)
    if r8.status_code != 200:
        error = j8.get("error", "???")
        errcode = j8.get("errcode", "???")
        print("Got error response: %s %s" % (errcode, error))


def login(server, username, password):

    path = "/_matrix/client/v3/login"
    url = server + path

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    client = BSSpeke.Client(user_id, domain, password)
    client_id = client.get_client_id()
    blind = client.generate_blind()
    print("Got client_id = [%s]" % client_id)
    print("Got blind = [%s]" % str(blind))

    # Request 1: Empty #####################################################
    print("\n\nRequest 1: New session\n")
    body = {
        "identifier": {
            "type": "m.id.user",
            "user": user_id
        }
    }
    r1 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r1.status_code)
    j1 = r1.json()
    session_id = j1.get("session", None)
    print("Got session id = [%s]" % session_id)
    flows = j1.get("flows", None)
    print("Got flows:")
    uia_stages = None
    for flow in flows:
        stages = flow.get("stages", [])
        print("\t", stages)
        if uia_stages is None:
            uia_stages = stages
    print("Got response: ", json.dumps(j1, indent=4))

    # Request 2: BS-SPEKE OPRF
    print("\n\nRequest 2: BS-SPEKE OPRF\n")
    client = BSSpeke.Client(user_id, domain, password)
    client_id = client.get_client_id()
    blind = client.generate_blind()
    print("Got client_id = [%s]" % client_id)
    print("Got blind = [%s]" % str(blind))

    oprf_params = j1["params"]["m.login.bsspeke-ecc.oprf"]
    curve = oprf_params["curve"]
    phf_params = oprf_params["phf_params"]
    blind_base64 = binascii.b2a_base64(blind, newline=False).decode('utf-8')
    print("Blind (base64) = [%s]" % blind_base64)

    body = {
        "identifier": {
            "type": "m.id.user",
            "user": user_id
        },
        "auth": {
            "type": "m.login.bsspeke-ecc.oprf",
            "curve": curve,
            "blind": blind_base64,
            "session": session_id
        }
    }
    r2 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r2.status_code)
    j2 = r2.json()
    print("Got response: ", json.dumps(j2, indent=4))
    completed = j2.get("completed", [])
    print("Got completed stages: ", completed)
    r2_params = j2.get("params", {})
    print("Got params: ", json.dumps(r2_params))
    if r2.status_code != 401:
        error = j2.get("error", "???")
        errcode = j2.get("errcode", "???")
        print("Got error response: %s %s" % (errcode, error))

    # Request 3: BS-SPEKE Verify
    print("\n\nRequest 3: BS-SPEKE Verify\n")
    verify_params = j2["params"]["m.login.bsspeke-ecc.verify"]
    blind_salt_str = verify_params["blind_salt"]
    B_str = verify_params["B"]
    blind_salt = base64.b64decode(blind_salt_str)
    B = base64.b64decode(B_str)
    B_hex = binascii.b2a_hex(B).decode('utf-8')
    print("\tB:\t[%s]" % B_hex)

    A_bytes = client.generate_A(blind_salt, phf_params)
    client.derive_shared_key(B)
    verifier_bytes = client.generate_verifier()

    A = binascii.b2a_base64(A_bytes, newline=False).decode('utf-8')
    A_hex = binascii.b2a_hex(A_bytes).decode('utf-8')
    print("\tA:\t[%s]" % A_hex)
    verifier = binascii.b2a_base64(verifier_bytes, newline=False).decode('utf-8')

    body = {
        "identifier": {
            "type": "m.id.user",
            "user": user_id
        },
        "auth": {
            "type": "m.login.bsspeke-ecc.verify",
            "A": A,
            "verifier": verifier,
            "session": session_id
        }
    }
    r3 = requests.post(url, headers=headers, json=body)
    print("Got status: %d" % r3.status_code)
    j3 = r3.json()
    completed = j3.get("completed", [])
    print("Got completed stages: ", completed)
    if r3.status_code != 200:
        error = j3.get("error", "???")
        errcode = j3.get("errcode", "???")
        print("Got error response: %s %s" % (errcode, error))




if __name__ == "__main__":

    #domain = "example.com"
    domain = sys.argv[1]
    username = "test_%04x" % random.getrandbits(16)
    user_id = "@%s:%s" % (username, domain)
    print("Running test with user id [%s]" % user_id)
    password = secrets.token_hex(8)

    server = "https://matrix.%s" % domain
    print("Got server = [%s]" % server)

    email = sys.argv[2]

    register(server, username, password, email)

    login(server, user_id, password)




