import socket
import threading
import json
import secrets
import hmac
import hashlib
import logging
import datetime
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def get_opcode_description(opcode):
    opcodes = {
        10: "KEY_VERIFICATION - Verifying established keys through handshake",
        20: "SESSION_TOKEN - Server sending encrypted session token",
        30: "CLIENT_ENC_DATA - Client sending Double DES encrypted data",
        40: "ENC_AGGR_RESULT - Server sending encrypted aggregated result",
        50: "DISCONNECT - Ending session"
    }
    return opcodes.get(opcode, "Unknown opcode")

class Server:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {} 
        self.session_tokens = {} 
        self.client_data = {}  
        
        # logging.basicConfig(
        #     filename=f'security_log_{datetime.datetime.now().strftime("%Y%m%d")}.log',
        #     level=logging.INFO,
        #     format='%(asctime)s - %(levelname)s - %(message)s'
        # )

    def handle_client(self, client_socket, addr):
        try:
            self.client_data[addr] = []
            
            
            private_key, public_key, p, g = self.generate_dh_keys()
            print(f"\nSending to client {addr}: Opcode 10 - {get_opcode_description(10)}")
            client_socket.send(json.dumps({
                'opcode': 10,
                'p': p,
                'g': g,
                'public_key': public_key
            }).encode())
            
            client_data = json.loads(client_socket.recv(1024).decode())
            print(f"\nReceived from client {addr}: Opcode {client_data['opcode']} - {get_opcode_description(client_data['opcode'])}")
            
            if client_data['opcode'] != 10:
                raise Exception("Invalid client response")
            client_public_key = client_data['public_key']
            
            shared_secret = pow(client_public_key, private_key, p)
            key1 = self.generate_des_key(shared_secret)
            key2 = self.generate_des_key(shared_secret + 1)
            
            print(f"\nGenerated Keys for client {addr}:")
            print(f"Key1: {key1.hex()}")
            print(f"Key2: {key2.hex()}")
            
            self.clients[addr] = {
                'socket': client_socket,
                'key1': key1,
                'key2': key2
            }
            
            session_token = self.generate_session_token()
            self.session_tokens[addr] = session_token
            encrypted_token = self.encrypt_des(key1, session_token)
            print(f"\nSending to client {addr}: Opcode 20 - {get_opcode_description(20)}")
            client_socket.send(json.dumps({
                'opcode': 20,
                'token': encrypted_token.hex()
            }).encode())
            
            while True:
                try:
                    data = client_socket.recv(1024).decode()
                    if not data:
                        break
                        
                    data = json.loads(data)
                    print(f"\nReceived from client {addr}: Opcode {data['opcode']} - {get_opcode_description(data['opcode'])}")
                    
                    if data['opcode'] == 30: 
                        print(f"\nProcessing message from client {addr}:")
                        
                        if data['token'] != session_token:
                            print("Invalid session token detected!")
                            logging.warning(f"Invalid session token attempt from {addr}")
                            client_socket.send(json.dumps({
                                'error': 'Invalid session token'
                            }).encode())
                            break
                            
                        received_hmac = data['hmac']
                        encrypted_hex = data['encrypted_data']
                        print(f"Received encrypted data: {encrypted_hex}")
                        print(f"Received HMAC: {received_hmac}")
                        
                        calculated_hmac = hmac.new(
                            key2,
                            encrypted_hex.encode('utf-8'),
                            hashlib.sha256
                        ).hexdigest()
                        print(f"Calculated HMAC: {calculated_hmac}")
                        
                        if received_hmac != calculated_hmac:
                            print("HMAC verification failed!")
                            logging.warning(f"Invalid HMAC detected from {addr}")
                            client_socket.send(json.dumps({
                                'error': 'Invalid HMAC'
                            }).encode())
                            continue
                            
                        print("\nServer-side Decryption Steps:")
                        first_decrypt = bytes.fromhex(encrypted_hex)
                        print(f"After converting hex to bytes: {first_decrypt.hex()}")
                        
                        second_decrypt = self.decrypt_des(key2, first_decrypt)
                        print(f"After first decryption (with key2): {second_decrypt}")
                        
                        final_decrypt = self.decrypt_des(key1, bytes.fromhex(second_decrypt))
                        print(f"Final decrypted message: {final_decrypt}")
                            
                        try:
                            numeric_data = float(final_decrypt)
                            self.client_data[addr].append(numeric_data)
                            
                            client_sum = sum(self.client_data[addr])
                            client_avg = client_sum / len(self.client_data[addr])
                            
                            agg_result = {
                                'sum': client_sum,
                                'average': client_avg,
                                'count': len(self.client_data[addr])
                            }
                            response = json.dumps(agg_result)
                            print(f"Client {addr} statistics: {agg_result}")
                        except ValueError:
                            response = f"Received: {final_decrypt}"
                        
                        print("\nPreparing response:")
                        first_encrypted = self.encrypt_des(key1, response)
                        print(f"After first encryption (key1): {first_encrypted.hex()}")
                        
                        final_encrypted = self.encrypt_des(key2, first_encrypted.hex())
                        encrypted_hex = final_encrypted.hex()
                        print(f"After second encryption (key2): {encrypted_hex}")
                        
                        response_hmac = hmac.new(
                            key2,
                            encrypted_hex.encode('utf-8'),
                            hashlib.sha256
                        ).hexdigest()
                        print(f"Generated response HMAC: {response_hmac}")
                        
                        print(f"\nSending to client {addr}: Opcode 40 - {get_opcode_description(40)}")
                        client_socket.send(json.dumps({
                            'opcode': 40,
                            'encrypted_data': encrypted_hex,
                            'hmac': response_hmac
                        }).encode())
                        
                    elif data['opcode'] == 50:  
                        print(f"\nClient {addr} requested disconnect: Opcode 50 - {get_opcode_description(50)}")
                        break
                        
                except json.JSONDecodeError:
                    client_socket.send(json.dumps({
                        'error': 'Invalid message format'
                    }).encode())
                    
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            if addr in self.clients:
                del self.clients[addr]
            if addr in self.session_tokens:
                del self.session_tokens[addr]
            if addr in self.client_data:
                del self.client_data[addr]


    def generate_dh_keys(self):
        p = 137
        g = 2
        private_key = secrets.randbelow(p)
        public_key = pow(g, private_key, p)
        return private_key, public_key, p, g

        
    def generate_des_key(self, shared_secret):
        key_bytes = str(shared_secret).encode()
        return hashlib.sha256(key_bytes).digest()[:8]
        
    def generate_session_token(self):
        return secrets.token_hex(16)
        
    def encrypt_des(self, key, data):
        cipher = DES.new(key, DES.MODE_ECB)
        padded_data = pad(data.encode(), DES.block_size)
        return cipher.encrypt(padded_data)
        
    def decrypt_des(self, key, encrypted_data):
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, DES.block_size).decode()
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        logging.info(f"Server started on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"\nNew connection from {addr}")
                logging.info(f"New client connected from {addr}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            logging.info("Server shutting down")
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    server = Server()
    server.start()