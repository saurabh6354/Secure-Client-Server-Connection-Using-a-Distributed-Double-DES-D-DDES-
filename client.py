import socket
import json
import secrets
import hmac
import hashlib
from Crypto.Cipher import DES
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

class Client:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key1 = None
        self.key2 = None
        self.session_token = None

    def connect(self):
        try:
            self.socket.connect((self.host, self.port))

            server_data = json.loads(self.socket.recv(1024).decode())
            print(f"\nReceived: Opcode {server_data['opcode']} - {get_opcode_description(server_data['opcode'])}")
            
            if server_data['opcode'] != 10:
                raise Exception("Invalid initial message from server")

            p = server_data['p']
            g = server_data['g']
            server_public_key = server_data['public_key']

            private_key, public_key = self.generate_dh_keys(p, g)
            print(f"\nSending: Opcode 10 - {get_opcode_description(10)}")
            self.socket.send(json.dumps({
                'opcode': 10,
                'public_key': public_key
            }).encode())

            shared_secret = pow(server_public_key, private_key, p)
            self.key1 = self.generate_des_key(shared_secret)
            self.key2 = self.generate_des_key(shared_secret + 1)
            
            print("\nGenerated Keys:")
            print(f"Key1: {self.key1.hex()}")
            print(f"Key2: {self.key2.hex()}")

            token_data = json.loads(self.socket.recv(1024).decode())
            print(f"\nReceived: Opcode {token_data['opcode']} - {get_opcode_description(token_data['opcode'])}")
            
            if token_data['opcode'] != 20:
                raise Exception("Invalid session token message")

            encrypted_token = bytes.fromhex(token_data['token'])
            self.session_token = self.decrypt_des(self.key1, encrypted_token)

            return True

        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def send_data(self, data):
        try:
            print("\nClient-side Encryption Steps:")
            print(f"Original message: {data}")
            
            first_encrypted = self.encrypt_des(self.key1, data)
            print(f"After first encryption (with key1): {first_encrypted.hex()}")
            
            final_encrypted = self.encrypt_des(self.key2, first_encrypted.hex())
            encrypted_hex = final_encrypted.hex()
            print(f"After second encryption (with key2): {encrypted_hex}")

            message_hmac = hmac.new(
                self.key2,
                encrypted_hex.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            print(f"Generated HMAC: {message_hmac}")

            print(f"\nSending: Opcode 30 - {get_opcode_description(30)}")
            message = {
                'opcode': 30,
                'encrypted_data': encrypted_hex,
                'token': self.session_token,
                'hmac': message_hmac
            }
            self.socket.send(json.dumps(message).encode() + b'\n')

            response_data = self.socket.recv(1024).decode()
            if not response_data:
                return None
                
            response = json.loads(response_data)
            print(f"\nReceived: Opcode {response['opcode']} - {get_opcode_description(response['opcode'])}")
            
            if 'error' in response:
                print(f"Server error: {response['error']}")
                return None

            if response['opcode'] == 40:
                print("\nDecrypting Server Response:")
                received_hmac = response['hmac']
                response_hex = response['encrypted_data']
                print(f"Received encrypted response: {response_hex}")
                
                calculated_hmac = hmac.new(
                    self.key2,
                    response_hex.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()

                if received_hmac != calculated_hmac:
                    print("Invalid server HMAC")
                    return None

                first_decrypt = bytes.fromhex(response_hex)
                print(f"After first decrypt: {first_decrypt.hex()}")
                
                second_decrypt = self.decrypt_des(self.key2, first_decrypt)
                print(f"After second decrypt: {second_decrypt}")
                
                final_decrypt = self.decrypt_des(self.key1, bytes.fromhex(second_decrypt))
                print(f"Final decrypted response: {final_decrypt}")
                return final_decrypt

        except Exception as e:
            print(f"Error sending data: {e}")
            return None

    def disconnect(self):
        try:
            print(f"\nSending: Opcode 50 - {get_opcode_description(50)}")
            self.socket.send(json.dumps({
                'opcode': 50
            }).encode())
        finally:
            self.socket.close()

    def generate_dh_keys(self, p, g):
        private_key = secrets.randbelow(p)
        public_key = pow(g, private_key, p)
        return private_key, public_key

    def generate_des_key(self, shared_secret):
        key_bytes = str(shared_secret).encode()
        return hashlib.sha256(key_bytes).digest()[:8]

    def encrypt_des(self, key, data):
        cipher = DES.new(key, DES.MODE_ECB)
        padded_data = pad(data.encode(), DES.block_size)
        return cipher.encrypt(padded_data)

    def decrypt_des(self, key, encrypted_data):
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, DES.block_size).decode()


def main():
    client = Client()
    if client.connect():
        try:
            while True:
                message = input("\nEnter message (or 'quit' to exit): ")
                if message.lower() == 'quit':
                    break

                response = client.send_data(message)
                if response:
                    print(f"\nServer response: {response}")

        finally:
            client.disconnect()


if __name__ == "__main__":
    main()