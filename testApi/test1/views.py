from django.shortcuts import render
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from rest_framework.parsers import JSONParser
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

# Create your views here.
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from cryptography.fernet import Fernet
from time import time
import json
import os
import base64
from .models import Notif
from .serializer import NotifSerializer


class ServerAPIView(APIView):

    flag = 0

    def start(self):
        if (flag == 0):
            run();
            flag = 10;
        else:
            #TODO: ?

        

    def run(self):
        server_private_key = decrypt_private_key_file()
        server_public_key = decrypt_public_key_file()
        print("server private key: " + server_private_key)
        print("server public ket: " + server_public_key)


    def decrypt_private_key_file(self):
                key = self.create_symmetric_key(self.user.decode('UTF-8'))
                username = self.read_user().decode('UTF-8')
                with open(username + '_priv_encrypted.pem', 'rb') as pub_dec_key:
                    cipher_pub_key = pub_dec_key.read()
                pub_dec_key.close()
                fernet = Fernet(key)
                decrypted = fernet.decrypt(cipher_pub_key)
                return decrypted.decode('UTF-8')

    def create_symmetric_key(self, username):
            if isinstance(username, bytes):
                username = username
            else:
                username = username.encode()

            salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                            backend=default_backend()
                            )
            symmetric_key = base64.urlsafe_b64encode(kdf.derive(username))
            return symmetric_key


    def read_user(self):
            with open('user.bin', 'rb') as user_file:
                user = user_file.read()
            user_file.close()
            return user




    def decrypt_public_key_file(self): 
                username = self.user.decode('UTF-8')
                key = self.create_symmetric_key(username)
                with open(username + '_pub_encrypted.pem', 'rb') as pub_dec_key:
                    cipher_pub_key = pub_dec_key.read()
                pub_dec_key.close()
                fernet = Fernet(key)
                return fernet.decrypt(cipher_pub_key)


    def create_new_block(self, chain):
            user = self.read_user().decode('UTF-8')
            block_data, correspond_len = self.implement_block_data()
            nonce = 0
            epoch = time()
            chain_data = json.dumps(block_data, sort_keys=True)
            chain_data = chain_data + str(round(epoch))
            block_hash = self.hash_block(chain_data + str(nonce))
            if block_hash[-2:] != '00':
                while block_hash[-2:] != '00':
                    nonce += 1
                    block_hash = self.hash_block(chain_data + str(nonce))
            signature = self.signature(block_hash).decode('UTF-8')
            public_key = self.decrypt_public_key_file()
            block = {
                "index": len(chain) + 1,
                "timestamp": epoch,
                "data": block_data,
                "signature": {"sign": signature, "user": user, "public_key": public_key.decode('UTF-8')},
                "previous_hash": chain[-1]['hash'],
                "hash": block_hash,
                "proof_of_work": nonce
            }
            return block


    def implement_block_data(self):
            data = {
                'id' : self.data['id'],
                'vessel' : self.data['vessel'],
                'customer' : self.data['customer'],
                'customer_data' : self.data['customer_data']
            }
            data = json.dumps(data, sort_keys=True)
            corresponds_public_Key = []
            if self.data['vessel']['provider']['blockchain_public_key']:
                corresponds_public_Key.append(
                    {'public_key': self.data['vessel']['provider']['blockchain_public_key'],
                    'user': self.data['vessel']['provider']['email']['key'] or self.data['vessel']['provider']['phone']['key']})
            if self.data['customer']['blockchain_public_key']:
                corresponds_public_Key.append({'public_key': self.data['customer']['blockchain_public_key'],
                                            'user': self.data['customer']['email']['key'] or
                                                    self.data['customer']['phone']['key']})
            data_collection = []
            for correspond_publicKey in corresponds_public_Key:
                key = Fernet.generate_key()
                f = Fernet(key)
                public_key_load = self.public_key_load(correspond_publicKey['public_key'])
                encrypted_key = self.encrypt_with_public_key(public_key_load, key)
                encrypted_key_b64 = base64.b64encode(encrypted_key)
                encrypted_data = f.encrypt(data.encode())
                encrypted_data_b64 = base64.b64encode(encrypted_data)
                data_collection.append({"user": correspond_publicKey['user'], "key": encrypted_key_b64.decode('UTF-8'),
                                        "contract_data": encrypted_data_b64.decode('UTF-8')})
            return data_collection, len(corresponds_public_Key)


    def hash_block(self, data):
                digest = hashes.Hash(hashes.SHA256())
                digest.update(data.encode())
                hashed = digest.finalize()
                return hashed.hex()


    def signature(self, hash):
                signature_data = hash
                private_key_pem = self.decrypt_private_key_file()
                private_key_load = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                    backend=default_backend()
                )
                signature = private_key_load.sign(
                    signature_data.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                return base64.b64encode(signature)





class Check_Notif(APIView):
    def get(self , request):
        notifications = Notif.objects.all()
        serializer = NotifSerializer(notifications, many = True)
        return Response(serializer.data) 


    def post(self, request):
        serializer = NorifSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data , status=status.HTTP_201_CREATED) ####TODO: status 201 , 400 ?? (search)
        return JsonResponse(serializer.errors, status= status.HTTP_400_BAD_REQUEST)
