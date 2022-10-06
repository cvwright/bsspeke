#!/bin/env python3

import sys

import base64
import binascii
import json
import requests
import random
import secrets

#domain = "example.com"
domain = sys.argv[1]
username = "test_%04x" % random.getrandbits(16)
user_id = "@%s:%s" % (username, domain)
print("Running test with user id [%s]" % user_id)
#password = "P@ssword1"
password = secrets.token_hex(10)

server = "https://matrix.%s" % sys.argv[1]
print("Got server = [%s]" % server)
path = "/_matrix/client/r0/register"

email = sys.argv[2]

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
print("Got response: ", json.dumps(j2, indent=2))
completed = j2.get("completed", [])
print("Got completed stages: ", completed)

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
completed = r3.json().get("completed", [])
print("Got completed stages: ", completed)

# Request 4: Username reservation ######################################
print("\n\nRequest 4: Username\n")
body = {
    "auth": {
        "type": "m.enroll.username",
        "username": username,
        "session": session_id
    }
}
r4 = requests.post(url, headers=headers, json=body)
print("Got status: %d" % r4.status_code)
completed = r4.json().get("completed", [])
print("Got completed stages: ", completed)

# Request 4: Request email token #######################################
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

# Request 5: Submit email token #######################################
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

# Request 6: Submit password
print("\n\nRequest 7: Password\n")
body = {
    "auth": {
        "type": "m.enroll.password",
        "new_password": password,
        "session": session_id
    }
}
r7 = requests.post(url, headers=headers, json=body)
print("Got status: %d" % r7.status_code)
j7 = r7.json()
completed = j7.get("completed", [])
print("Got completed stages: ", completed)
if r7.status_code != 200:
    error = j7.get("error", "???")
    errcode = j7.get("errcode", "???")
    print("Got error response: %s %s" % (errcode, error))
