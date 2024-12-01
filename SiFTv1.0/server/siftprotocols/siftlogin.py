#python3

import time
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error



class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp, key):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.timestamp_range = 1
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None 
        self.key = key


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):
        login_req_str = str(time.time())
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        login_req_str += self.delimiter + login_req_struct['client_random'].hex()
        return login_req_str.encode(self.coding)

    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['timestamp'] = login_req_fields[0]
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = bytes.fromhex(login_req_fields[3])
        return login_req_struct



    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):

        login_res_str = login_res_struct['request_hash'].hex()
        login_res_str += self.delimiter + login_res_struct['server_random'].hex() 

        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg(self.key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        # check client timestamp and create window
        client_time = int(login_req_struct['timestamp'])
        server_time = time.time()

        if client_time < server_time - self.timestamp_range or client_time > server_time + self.timestamp_range:
            raise SiFT_LOGIN_Error('Timestamp out of expected range')

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = get_random_bytes(16)
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload, self.key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG         

        # genearting session key
        client_random = login_req_struct['client_random']
        server_random = login_res_struct['server_random']

        session_key = HKDF(client_random + server_random, 32, request_hash, SHA256)
        self.mtp.set_session_key(session_key)
        
        return login_req_struct['username']

        # NEW SERVER LOGIN KEEP FOR ETK
    # def handle_login_server(self):
    #     # Receive and parse the login request
    #     msg_type, msg_payload = self.mtp.receive_msg()
    #     if msg_type != self.mtp.type_login_req:
    #         raise SiFT_LOGIN_Error('Expected login request')

    #     login_req_struct = self.parse_login_req(msg_payload[:-256])
    #     etk = msg_payload[-256:]

    #     # Decrypt the AES key using the server's private RSA key
    #     with open('serverprivkey.pem', 'rb') as f:
    #         data = f.read()
    #         pwd = b'1234'
    #         private_key = RSA.import_key(data, pwd)
    #     cipher_rsa = PKCS1_OAEP.new(private_key)
    #     temp_key = cipher_rsa.decrypt(etk)

    #     # Verify and process the request
    #     if not self.verify_login(login_req_struct, temp_key):
    #         raise SiFT_LOGIN_Error('Invalid login')

    #     username = login_req_struct['username']
        
    #     # processing login request
    #     hash_fn = SHA256.new()
    #     hash_fn.update(msg_payload)
    #     request_hash = hash_fn.digest()

    #     login_req_struct = self.parse_login_req(msg_payload)
    #     # building login response
    #     login_res_struct = {}
    #     login_res_struct['request_hash'] = request_hash
    #     msg_payload = self.build_login_res(login_res_struct)

    #     if self.DEBUG:
    #         print("Received Login Request:")
    #         print(f"{login_req_struct['timestamp']}\\n{username}\\n{login_req_struct['password']}\\n"
    #                 f"{login_req_struct['client_random'].hex()}")
    #         print("MTP Message Components:")
    #         print(f"  EPD ({len(encrypted_payload)}):   {encrypted_payload.hex()}")
    #         print(f"  ETK ({len(etk)}):   {etk.hex()}")


    #     # Generate server_random and derive the final session key
    #     server_random = get_random_bytes(16)
    #     final_key = self.derive_session_key(
    #         temp_key, login_req_struct['client_random'], server_random
    #     )

    #     # Send login response
    #     response = f"{SHA256.new(msg_payload).hexdigest()}{self.delimiter}" \
    #                 f"{server_random.hex()}".encode(self.coding)

    #     if self.DEBUG:
    #         print("Login Response Message:")
    #         print(f"{request_hash.hex()}\\n{server_random.hex()}")
    #         print("MTP Message Components:")
    #         print(f"  RES ({len(response_payload)}):   {response_payload.hex()}")

    #     self.mtp.send_msg(self.mtp.type_login_res, response)

    #     return final_key, login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = get_random_bytes(16)
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        
        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload, self.key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg(self.key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # generating session key(same as server side)
        client_random = login_req_struct['client_random']
        server_random = login_res_struct['server_random']
        
        session_key = HKDF(client_random + server_random, 32, request_hash, SHA256)
        self.mtp.set_session_key(session_key)

    
    # def handle_login_client(self, username, password):
    #     # Generate temporary AES key and client_random
    #     temp_key = get_random_bytes(32)
    #     client_random = get_random_bytes(16)

    #     # Encrypt the temporary AES key with the server's public RSA key
    #     with open('serverpubkey.pem', 'rb') as f:
    #         public_key = RSA.import_key(f.read())
    #     cipher_rsa = PKCS1_OAEP.new(public_key)
    #     etk = cipher_rsa.encrypt(temp_key)

    #     # Build login request
    #     login_req_struct = {
    #         'timestamp': str(time.time()),
    #         'username': username,
    #         'password': password,
    #         'client_random': client_random,
    #         'etk': etk
    #     }
    #     payload, etk = self.build_login_req(login_req_struct)
    #     message = payload + etk

    #     if self.DEBUG:
    #         print("Login Request Message:")
    #         print(f"{login_req_struct['timestamp']}\\n{username}\\n{password}\\n{client_random.hex()}")
    #         print("MTP Message Components:")
    #         print(f"  HDR ({len(message)}):   {message[:16].hex()}")
    #         print(f"  EPD ({len(payload)}):   {payload.hex()}")
    #         print(f"  ETK ({len(etk)}):   {etk.hex()}")

    #     # Send login request
    #     self.mtp.send_msg(self.mtp.type_login_req, payload + etk)

    #     # Receive and parse login response
    #     msg_type, msg_payload = self.mtp.receive_msg()
    #     if msg_type != self.mtp.type_login_res:
    #         raise SiFT_LOGIN_Error('Expected login response')

    #     fields = msg_payload.decode(self.coding).split(self.delimiter)
    #     request_hash = bytes.fromhex(fields[0])
    #     server_random = bytes.fromhex(fields[1])

    #     if self.DEBUG:
    #         print("Received Login Response:")
    #         print(f"{request_hash.hex()}\\n{server_random.hex()}")

    #     # Derive final session key
    #     return self.derive_session_key(temp_key, client_random, server_random)

