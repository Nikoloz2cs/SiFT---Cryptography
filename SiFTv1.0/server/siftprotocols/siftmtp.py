#python3

import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rand = 6
		self.size_msg_hdr_rsv = 2
		self.size_mac = 12
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.sqn = 0


	# sets a session key
	def set_session_key(self, session_key):
		self.session_key = session_key

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i : i + self.size_msg_hdr_ver], i + self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i : i + self.size_msg_hdr_typ], i + self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i : i + self.size_msg_hdr_len], i + self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i : i + self.size_msg_hdr_sqn], i + self.size_msg_hdr_sqn
		parsed_msg_hdr['rand'], i = msg_hdr[i : i + self.size_msg_hdr_rand], i + self.size_msg_hdr_rand
		parsed_msg_hdr['rsv'], i = msg_hdr[i : i + self.size_msg_hdr_rsv], i + self.size_msg_hdr_rsv
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		#print("In receive bytes")
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			#print("inputted n:", n)
			try:
				chunk = self.peer_socket.recv(n - bytes_count)
				#print("in receive bytes try statement")
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		#print("End of recieve bytes")
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self, key=None):
		if not key:
			key = self.session_key

		try:
			#print("R In first try statement")
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		if int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big') < self.sqn:
			raise SiFT_MTP_Error('Sequence number is incorrect')
		else:
			self.sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
			#print("R assigend seq num")

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			if parsed_msg_hdr['typ'] == self.type_login_req:
				size_etk = 256
			else:
				size_etk = 0
			enc_msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - size_etk- self.size_mac)
			#print("R encrypted message body built")
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)


		if len(enc_msg_body) != msg_len - self.size_msg_hdr - self.size_mac - size_etk: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		# receive the MAC
		try:
			mac = self.receive_bytes(self.size_mac)
			#print("R mac recieved")
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('MAC was incorrectly received -->' + e.err_msg)

		# receive the etk
		if parsed_msg_hdr['typ'] == self.type_login_req:
			try:
				etk = self.receive_bytes(size_etk)
				#print('etk receiveds')
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('MAC was incorrectly received -->' + e.err_msg)
			cipher_key = PKCS1_OAEP.new(key)
			tk = cipher_key.decrypt(etk)
			#print("R temporary key in use")

			
			cipher_payload = AES.new(tk, AES.MODE_GCM, mac_len=12, nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rand'])
			cipher_payload.update(msg_hdr)
			msg_body = cipher_payload.decrypt_and_verify(enc_msg_body, mac)
			
			self.tk = tk

		elif parsed_msg_hdr['typ'] == self.type_login_res:
			cipher_payload = AES.new(self.tk, AES.MODE_GCM, mac_len = 12, nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rand'])
			cipher_payload.update(msg_hdr)
			msg_body = cipher_payload.decrypt_and_verify(enc_msg_body, mac)
			print('Login response received')


		else:
			cipher_payload = AES.new(self.session_key, AES.MODE_GCM, mac_len = 12, nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rand'])
			cipher_payload.update(msg_hdr)
			msg = cipher_payload.decrypt_and_verify(enc_msg_body, mac)


		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(enc_msg_body)) + '): ')
			print(enc_msg_body.hex())
			print('MAC (' + str(len(mac)) + '):' + mac.hex())
			if parsed_msg_hdr['typ'] == self.type_login_req:
				print('ETK (' + str(len(etk)) + '):')
				print(etk.hex())
			print('------------------------------------------')
		# DEBUG 

		return parsed_msg_hdr['typ'], msg_body


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload, key = None):
		if not key:
			key = self.session_key

		self.sqn += 1

		# build message, with exception for login request
		msg_size = self.size_msg_hdr + len(msg_payload) + 12
		if msg_type == self.type_login_req:
			msg_size += 256

		# build message header
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_sqn = self.sqn.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_rand = get_random_bytes(6)
		msg_rsv = b'\x00\x00'
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rand + msg_rsv

		if msg_type == self.type_login_req:
			temporary_key = get_random_bytes(32)
			self.tk = temporary_key

			cipher_key = PKCS1_OAEP.new(key)
			cipher_payload = AES.new(temporary_key, AES.MODE_GCM, mac_len = 12, nonce = msg_sqn + msg_rand)
			cipher_payload.update(msg_hdr)

			enc_payload, mac = cipher_payload.encrypt_and_digest(msg_payload)
			enc_temp_key = cipher_key.encrypt(temporary_key)
			enc_msg = msg_hdr + enc_payload + mac + enc_temp_key
			

		elif msg_type == self.type_login_res:
			cipher_payload = AES.new(self.tk, AES.MODE_GCM, mac_len = 12, nonce = msg_sqn + msg_rand)
			cipher_payload.update(msg_hdr)

			enc_payload, mac = cipher_payload.encrypt_and_digest(msg_payload)
			enc_msg = msg_hdr + enc_payload + mac

		else:
			cipher_payload = AES.new(self.session_key, AES.MODE_GCM, mac_len = 12, nonce = msg_sqn + msg_rand)
			cipher_payload.update(msg_hdr)
			enc_payload, mac = cipher_payload.encrypt_and_digest(msg_payload)

			enc_msg = msg_hdr + enc_payload + mac


		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('MAC (' + str(len(mac)) + '):' + mac.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(enc_msg)
			print("message sent")
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)


