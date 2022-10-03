/*
 * demo.c - Example use of the BS-SPEKE functions
 *
 * Author: Charles V. Wright <cvwright@futo.org>
 * 
 * Copyright (c) 2022 FUTO Holdings, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/bsspeke.h"

typedef struct {
    uint8_t salt[32];
    size_t salt_len;

    uint8_t P[32];
    uint8_t V[32];

    uint32_t phf_blocks;
    uint32_t phf_iterations;
} bsspeke_user_info_t;

int demo_setup(bsspeke_user_info_t *user_info)
{
    bsspeke_client_ctx client;
    bsspeke_server_ctx server;

    puts("");
    puts("Starting Setup");

    const char *client_id = "@alice:example.com";
    const char *server_id = "bob.example.com";
    const char *password = "P@ssword1";

    // Because we got rid of all the custom message
    // structs, we need to pretend to be the network
    // ferrying messages back and forth between the
    // client and server.
    // More than that, we have to pretend to be the
    // network interface code that marshals and
    // unmarshals all of these variables out of
    // JSON or whatever.
    uint8_t blind[32];
    uint8_t blind_salt[32];

    puts("");
    puts("Setup: Initializing client");
    bsspeke_client_init(&client,
                        client_id, strlen(client_id),
                        server_id, strlen(server_id),
                        password, strlen(password));

    puts("Setup: Initializing server");
    bsspeke_server_init(&server,
                        server_id, strlen(server_id),
                        client_id, strlen(client_id));

    puts("");
    puts("Setup: Client generating message 1");
    bsspeke_client_generate_blind(blind, &client);

    puts("");
    puts("Setup: Server generating message 2");
    memset(user_info->salt, '\xff', 32);
    user_info->salt_len = 32;
    bsspeke_server_blind_salt(blind_salt,
                              blind,
                              user_info->salt, user_info->salt_len);

    puts("");
    puts("Setup: Client generating message 3");
    user_info->phf_blocks = 100000;
    user_info->phf_iterations = 3;
    bsspeke_client_generate_P_and_V(user_info->P,
                                    user_info->V,
                                    blind_salt,
                                    user_info->phf_blocks,
                                    user_info->phf_iterations,
                                    &client);
    /*
    puts("");
    puts("Setup: Server processing message 3");
    bsspeke_server_setup_process_message3(&msg3, user_info, &server);
    */

    puts("");
    puts("Setup: Done");

    return 0;
}

int demo_login(bsspeke_user_info_t *user_info)
{
    bsspeke_client_ctx client;
    bsspeke_server_ctx server;

    puts("");
    puts("Starting Login");

    const char *client_id = "@alice:example.com";
    const char *server_id = "bob.example.com";
    const char *password = "P@ssword1";

    puts("");
    puts("Login: Initializing client");
    bsspeke_client_init(&client,
                        client_id, strlen(client_id),
                        server_id, strlen(server_id),
                        password, strlen(password));

    puts("Login: Initializing server");
    bsspeke_server_init(&server,
                        server_id, strlen(server_id),
                        client_id, strlen(client_id));

    // Again we have to pretend to be the network and the
    // data marshalling layers
    uint8_t blind[32];
    uint8_t blind_salt[32];

    uint8_t client_verifier[32];
    uint8_t server_verifier[32];

    puts("");
    puts("Login: Client generating message 1");
    bsspeke_client_generate_blind(blind, &client);

    puts("");
    puts("Login: Server generating message 2");
    bsspeke_server_blind_salt(blind_salt, blind,
                              user_info->salt,
                              user_info->salt_len);
    bsspeke_server_generate_B(user_info->P, &server);

    puts("");
    puts("Login: Client generating message 3");
    int rc_A = bsspeke_client_generate_A(blind_salt,
                                         user_info->phf_blocks,
                                         user_info->phf_iterations,
                                         &client);
    if( rc_A != 0 ) {
        puts("Login failed to hash user's password");
        return -1;
    }
    bsspeke_client_derive_shared_key(server.B, &client);
    bsspeke_client_generate_verifier(client_verifier, &client);

    puts("");
    puts("Login: Server generating message 4");
    bsspeke_server_derive_shared_key(client.A,
                                     user_info->V,
                                     &server);
    int rc_s = bsspeke_server_verify_client(client_verifier,
                                            &server);
    if( rc_s != 0 ) {
        puts("Server failed to verify client.");
        puts("LOGIN FAILED");
        return -1;
    }
    bsspeke_server_generate_verifier(server_verifier,
                                     &server);

    puts("");
    puts("Login: Client verifying message 4");
    int rc_c = bsspeke_client_verify_server(server_verifier,
                                            &client);
    if( rc_c != 0 ) {
        puts("Client failed to verify server.");
        puts("LOGIN FAILED");
        return -1;
    }

    return 0;

}

int main(int argc, char *argv[])
{
    // Here we're pretending to be the server's long-term storage
    bsspeke_user_info_t user_info;

    int rc = 0;

    if( (rc = demo_setup(&user_info)) != 0 ) {
        puts("Setup failed :(");
        exit(-1);
    }

    if( (rc = demo_login(&user_info)) != 0 ) {
        puts("Login failed :(");
        exit(-1);
    }

    return 0;
}
