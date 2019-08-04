
m Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os, sys

def decrypt(file):

    file_in = open(file, "rb")
    file_out = open(str(file[:-4]), "wb")
    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
       [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file_out.write(data)
    print(file + " РАСШИФРОВАН!")
    os.remove(file)

def walk(dir):
	for name in os.listdir(dir):
		path = os.path.join(dir, name)
		if os.path.isfile(path): decrypt(path)
		else: walk(path)
#Тут фигачь ту деректорию где прячеш файлы
walk("/var/www")
print("---------------------------------------------------------------" )
