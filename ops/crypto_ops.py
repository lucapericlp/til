from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def encrypt_file(absolute_txt_path,absolute_pubkey_path,secret_code):

	txt_name = ''.join(absolute_txt_path.split("/")[-1:])[:-4]
	output_path = ('/'.join(absolute_txt_path.split("/")[:-1]))+'/'
	file_out = open(output_path+txt_name+".bin","wb")

	#get text data
	data = '';
	with open(absolute_txt_path,"r") as myfile:
		data = myfile.read();
	data = data.encode('utf-8')


	#get encoded .bin pub key
	encoded_key = open(absolute_pubkey_path,"rb").read()
	recipient_key = RSA.import_key(encoded_key, passphrase=secret_code)

	session_key = get_random_bytes(16)
	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	enc_session_key = cipher_rsa.encrypt(session_key)
	cipher_aes = AES.new(session_key,AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(data)
	[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

def decrypt_file(absolute_encrypted_txt_path,absolute_privkey_path,secret_code):
	txt_name = ''.join(absolute_encrypted_txt_path.split("/")[-1:])[:-4]
	output_path = ('/'.join(absolute_encrypted_txt_path.split("/")[:-1]))+'/'
	file_out = open(output_path+txt_name+".txt","wb")
	file_in = open(absolute_encrypted_txt_path,"rb")

	encoded_key = open(absolute_privkey_path,"rb").read()
	private_key = RSA.import_key(encoded_key,passphrase=secret_code)

	enc_session_key, nonce, tag, ciphertext = \
   		[ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)

	# Decrypt the data with the AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	data = cipher_aes.decrypt_and_verify(ciphertext, tag)
	file_out.write(data)
