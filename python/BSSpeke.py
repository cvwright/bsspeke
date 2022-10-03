#import base64

from _bsspeke_cffi import ffi, lib

class Client:
    
    def __init__(self, user_id, server_id, password):
        uid_utf8 = user_id.encode('utf-8')
        print("uid_utf8:", uid_utf8.decode('utf-8'), len(uid_utf8))
        sid_utf8 = server_id.encode('utf-8')
        print("sid_utf8:", sid_utf8.decode('utf-8'), len(sid_utf8))
        pwd_utf8 = password.encode('utf-8')
        print("pwd_utf8:", pwd_utf8.decode('utf-8'), len(pwd_utf8))

        from _bsspeke_cffi import ffi, lib
        self.ffi = ffi
        self.lib = lib

        self.ctx = self.ffi.new("bsspeke_client_ctx *")
        self.lib.bsspeke_client_init(self.ctx,
                                     uid_utf8, len(uid_utf8),
                                     sid_utf8, len(sid_utf8),
                                     pwd_utf8, len(pwd_utf8))

    def generate_blind(self):
        blind = bytes(32)
        self.lib.bsspeke_client_generate_blind(blind, self.ctx)
        return blind


    def get_client_id(self):
        clientid_len = self.ctx.client_id_len
        client_id_bytes = bytes(ffi.buffer(self.ctx.client_id, self.ctx.client_id_len))
        client_id = client_id_bytes.decode('utf-8')
        #print("ClientId string = [%s]" % client_id)
        return client_id


    def generate_P_and_V(self, blind_salt, phf_params):
        P = bytes(32)
        V = bytes(32)
        phf_blocks = phf_params["blocks"]
        phf_iterations = phf_params["iterations"]
        self.lib.bsspeke_client_generate_P_and_V(P, V,
                                                 blind_salt,
                                                 phf_blocks, phf_iterations,
                                                 self.ctx)
        return P,V
#        request = {}
#        request["P"] = base64.b64encode(P)
#        request["V"] = base64.b64encode(V)
#        request["phf"] = {}
#        request["phf"]["name"] = "argon2i"
#        request["phf"]["blocks"] = phf_blocks
#        request["phf"]["iterations"] = phf_iterations
#
#        return request

    def generate_A(self, blind_salt, phf_params):
        phf_blocks = phf_params["blocks"]
        phf_iterations = phf_params["iterations"]
        self.lib.bsspeke_client_generate_A(blind_salt,
                                           phf_blocks,
                                           phf_iterations,
                                           self.ctx)
        A = bytes(ffi.buffer(self.ctx.A, 32))
        return A

    def derive_shared_key(self, B):
        self.lib.bsspeke_client_derive_shared_key(B, self.ctx)

    def generate_verifier(self):
        client_verifier = bytes(32)
        self.lib.bsspeke_client_generate_verifier(client_verifier, self.ctx)
        return client_verifier

    def verify_server(self, server_verifier):
        rc = self.lib.bsspeke_client_verify_server(server_verifier, self.ctx)
        if rc != 0:
            return False
        else:
            return True


class Server:
    def __init__(self, server_id, user_id):
        sid_utf8 = server_id.encode('utf-8')
        print("sid_utf8:", sid_utf8.decode('utf-8'), len(sid_utf8))
        uid_utf8 = user_id.encode('utf-8')
        print("uid_utf8:", uid_utf8.decode('utf-8'), len(uid_utf8))

        from _bsspeke_cffi import ffi, lib
        self.ffi = ffi
        self.lib = lib
        
        self.ctx = self.ffi.new("bsspeke_server_ctx *")
        self.lib.bsspeke_server_init(self.ctx,
                                     sid_utf8, len(sid_utf8),
                                     uid_utf8, len(uid_utf8))

    def blind_salt(self, blind, salt):
        blind_salt = bytes(32)
        self.lib.bsspeke_server_blind_salt(blind_salt, blind, salt, len(salt))
        return blind_salt

    def generate_B(self, P):
        self.lib.bsspeke_server_generate_B(P, self.ctx)
        B = bytes(self.ffi.buffer(self.ctx.B, 32))
        return B

    def derive_shared_key(self, A, V):
        self.lib.bsspeke_server_derive_shared_key(A, V, self.ctx)
        
    def verify_client(self, client_verifier):
        rc = self.lib.bsspeke_server_verify_client(client_verifier, self.ctx)
        if rc != 0:
            return False
        else:
            return True

    def generate_verifier(self):
        server_verifier = bytes(32)
        self.lib.bsspeke_server_generate_verifier(server_verifier, self.ctx)
        return server_verifier

