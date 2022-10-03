#!/bin/env python3

from _bsspeke_cffi import ffi, lib

def bsspeke_setup():
    client = ffi.new("bsspeke_client_ctx *")
    lib.bsspeke_client_init(client, b"@alice:example.com", 18, b"example.com", 11, b"P@ssword1", 9)

    server = ffi.new("bsspeke_server_ctx *")
    lib.bsspeke_server_init(server, b"example.com", 11, b"@alice:example.com", 18)

    print("Message 1")
    blind = bytes(32)
    lib.bsspeke_client_generate_blind(blind, client)

    print("Message 2")
    salt = b"\xff" * 32
    blind_salt = bytes(32)
    lib.bsspeke_server_blind_salt(blind_salt, blind, salt, 32)

    print("Message 3")
    P = bytes(32)
    V = bytes(32)
    phf_blocks = 100000
    phf_iterations = 3
    lib.bsspeke_client_generate_P_and_V(P, V, blind_salt, phf_blocks, phf_iterations, client)

    return (P,V,phf_blocks,phf_iterations)


def bsspeke_login(user_params):
    client = ffi.new("bsspeke_client_ctx *")
    lib.bsspeke_client_init(client, b"@alice:example.com", 18, b"example.com", 11, b"P@ssword1", 9)

    server = ffi.new("bsspeke_server_ctx *")
    lib.bsspeke_server_init(server, b"example.com", 11, b"@alice:example.com", 18)

    P,V,phf_blocks,phf_iterations = user_params

    print("Message 1")
    blind = bytes(32)
    lib.bsspeke_client_generate_blind(blind, client)

    print("Message 2")
    salt = b"\xff" * 32
    blind_salt = bytes(32)
    lib.bsspeke_server_blind_salt(blind_salt, blind, salt, 32)
    lib.bsspeke_server_generate_B(P, server);
    B = bytes(ffi.buffer(server.B, 32))

    print("Message 3")
    lib.bsspeke_client_generate_A(blind_salt, phf_blocks, phf_iterations, client)
    A = bytes(ffi.buffer(client.A, 32))
    lib.bsspeke_client_derive_shared_key(B, client)
    client_verifier = bytes(32)
    lib.bsspeke_client_generate_verifier(client_verifier, client)

    print("Message 4")
    lib.bsspeke_server_derive_shared_key(A, V, server)
    rc_server = lib.bsspeke_server_verify_client(client_verifier, server)
    if rc_server != 0:
        print("ERROR: Server failed to verify client")
        print("LOGIN FAILED")
        return -1
    server_verifier = bytes(32)
    lib.bsspeke_server_generate_verifier(server_verifier, server)

    print("Wrapping Up")
    rc_client = lib.bsspeke_client_verify_server(server_verifier, client)
    if rc_client != 0:
        print("ERROR: Client failed to verify server")
        print("LOGIN FAILED")
        return -1

    return 0


if __name__ == "__main__":
    print("Creating user info object to represent the server's long-term storage")

    print("\n\nStarting setup...")
    user_params = bsspeke_setup()

    print("\n\nRunning login...")
    rc = bsspeke_login(user_params)
    if rc != 0:
        print("BS-SPEKE login failed :(")
    else:
        print("SUCCESS!!!!!")
