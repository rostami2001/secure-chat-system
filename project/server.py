import socket
import threading
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    return base64.b64encode(public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode('utf-8')

def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def read_user_data():
    if os.path.exists('user_data.json'):
        with open('user_data.json', 'r') as file:
            return json.load(file)
    return {}

def write_user_data(data):
    with open('user_data.json', 'w') as file:
        json.dump(data, file)

def read_group_data():
    if os.path.exists('group_data.json'):
        with open('group_data.json', 'r') as file:
            return json.load(file)
    return {}

def write_group_data(data):
    with open('group_data.json', 'w') as file:
        json.dump(data, file)

def read_messages_data():
    if os.path.exists('messages_data.json'):
        with open('messages_data.json', 'r') as file:
            return json.load(file)
    return {}

def write_messages_data(data):
    with open('messages_data.json', 'w') as file:
        json.dump(data, file)

class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.address = address

    def run(self):
        try:
            request = json.loads(self.client_socket.recv(1024).decode('utf-8'))
            if request['type'] == 'register':
                self.register(request)
            elif request['type'] == 'login':
                self.login(request)
            elif request['type'] == 'private_chat':
                self.private_chat(request)
            elif request['type'] == 'create_group':
                self.create_group(request)
            elif request['type'] == 'add_to_group':
                self.add_to_group(request)
            elif request['type'] == 'remove_from_group':
                self.remove_from_group(request)
            elif request['type'] == 'send_group_message':
                self.send_group_message(request)
            elif request['type'] == 'fetch_messages':
                self.fetch_messages(request)
            elif request['type'] == 'change_role':
                self.change_role(request)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.client_socket.close()

    def register(self, request):
        users = read_user_data()
        email = request['email']
        if (email in users) or (not email):
            self.client_socket.send(
                json.dumps({'status': 'error', 'message': 'Email already registered or invalid'}).encode('utf-8'))
            return

        password = request['password']
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        private_key, public_key = generate_key_pair()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        role = request.get('role', 'user')
        users[email] = {
            'username': request['username'],
            'password': key.decode('utf-8'),
            'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),
            'private_key': private_key_pem,
            'public_key': public_key_pem,
            'role': role
        }
        write_user_data(users)
        self.client_socket.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def login(self, request):
        users = read_user_data()
        email = request['email']
        if email not in users:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Invalid email or password'}).encode('utf-8'))
            return

        password = request['password']
        user = users[email]
        salt = base64.urlsafe_b64decode(user['salt'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        if key.decode('utf-8') != user['password']:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Invalid email or password'}).encode('utf-8'))
            return

        self.client_socket.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def change_role(self, request):
        users = read_user_data()
        email = request['email']
        new_role = request['role']
        requester_email = request['requester_email']

        if requester_email not in users or users[requester_email]['role'] != 'super admin':
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Permission denied'}).encode('utf-8'))
            return

        if email not in users:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'User not found'}).encode('utf-8'))
            return

        users[email]['role'] = new_role
        write_user_data(users)
        self.client_socket.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def private_chat(self, request):
        users = read_user_data()
        messages = read_messages_data()
        sender = request['sender']
        receiver = request['receiver']
        message = request['message']

        if receiver not in users:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'User not found'}).encode('utf-8'))
            return

        sender_private_key = serialization.load_pem_private_key(
            users[sender]['private_key'].encode('utf-8'),
            password=None
        )

        receiver_public_key = serialization.load_pem_public_key(
            users[receiver]['public_key'].encode('utf-8')
        )

        encrypted_message = encrypt_message(receiver_public_key, message)
        signature = sign_message(sender_private_key, message)

        if receiver not in messages:
            messages[receiver] = []

        messages[receiver].append({
            'sender': sender,
            'encrypted_message': encrypted_message,
            'signature': signature
        })

        write_messages_data(messages)

        self.client_socket.send(json.dumps({
            'status': 'success',
            'encrypted_message': encrypted_message,
            'signature': signature
        }).encode('utf-8'))

    def create_group(self, request):
        users = read_user_data()
        email = request['creator']

        if email not in users or users[email]['role'] not in ['admin', 'super admin']:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Permission denied'}).encode('utf-8'))
            return

        groups = read_group_data()
        group_id = request['group_id']
        creator = request['creator']

        if group_id in groups:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Group ID already exists'}).encode('utf-8'))
            return

        groups[group_id] = {
            'creator': creator,
            'members': [creator]
        }
        write_group_data(groups)
        self.client_socket.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def add_to_group(self, request):
        groups = read_group_data()
        group_id = request['group_id']
        user_to_add = request['user_to_add']
        requester_email = request['requester_email']

        if group_id not in groups:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Group not found'}).encode('utf-8'))
            return

        if groups[group_id]['creator'] != requester_email:
            self.client_socket.send(
                json.dumps({'status': 'error', 'message': 'Only group creator can add members'}).encode('utf-8'))
            return

        if user_to_add in groups[group_id]['members']:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'User already in group'}).encode('utf-8'))
            return

        groups[group_id]['members'].append(user_to_add)
        write_group_data(groups)
        self.client_socket.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def remove_from_group(self, request):
        groups = read_group_data()
        group_id = request['group_id']
        user_to_remove = request['user_to_remove']
        requester_email = request['requester_email']

        if group_id not in groups:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Group not found'}).encode('utf-8'))
            return

        if groups[group_id]['creator'] != requester_email:
            self.client_socket.send(
                json.dumps({'status': 'error', 'message': 'Only group creator can remove members'}).encode('utf-8'))
            return

        if user_to_remove not in groups[group_id]['members']:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'User not in group'}).encode('utf-8'))
            return

        groups[group_id]['members'].remove(user_to_remove)
        write_group_data(groups)
        self.client_socket.send(json.dumps({'status': 'success'}).encode('utf-8'))

    def send_group_message(self, request):
        users = read_user_data()
        messages = read_messages_data()
        groups = read_group_data()
        sender = request['sender']
        group_id = request['group_id']
        message = request['message']

        if group_id not in groups:
            self.client_socket.send(json.dumps({'status': 'error', 'message': 'Group not found'}).encode('utf-8'))
            return

        if sender not in groups[group_id]['members']:
            self.client_socket.send(
                json.dumps({'status': 'error', 'message': 'You are not a member of this group'}).encode('utf-8'))
            return

        sender_private_key = serialization.load_pem_private_key(
            users[sender]['private_key'].encode('utf-8'),
            password=None
        )

        group_members = groups[group_id]['members']
        encrypted_messages = {}
        signatures = {}

        for member in group_members:
            if member == sender:
                continue
            receiver_public_key = serialization.load_pem_public_key(
                users[member]['public_key'].encode('utf-8')
            )
            encrypted_message = encrypt_message(receiver_public_key, message)
            signature = sign_message(sender_private_key, message)
            encrypted_messages[member] = encrypted_message
            signatures[member] = signature

            if member not in messages:
                messages[member] = []

            messages[member].append({
                'sender': sender,
                'group_id': group_id,
                'group_name': group_id,
                'encrypted_message': encrypted_message,
                'signature': signature
            })

        write_messages_data(messages)

        self.client_socket.send(json.dumps({
            'status': 'success',
            'encrypted_messages': encrypted_messages,
            'signatures': signatures
        }).encode('utf-8'))

    def fetch_messages(self, request):
        messages = read_messages_data()
        email = request['email']

        if email not in messages:
            self.client_socket.send(json.dumps({'status': 'success', 'messages': []}).encode('utf-8'))
            return

        user_messages = messages[email]

        users = read_user_data()
        private_key = serialization.load_pem_private_key(
            users[email]['private_key'].encode('utf-8'),
            password=None
        )

        decrypted_messages = []
        for message in user_messages:
            sender = message['sender']
            encrypted_message = message['encrypted_message']
            decrypted_message = decrypt_message(private_key, encrypted_message)
            decrypted_messages.append({
                'sender': sender,
                'group_id': message.get('group_id', None),
                'group_name': message.get('group_name', None),
                'message': decrypted_message
            })

        self.client_socket.send(json.dumps({'status': 'success', 'messages': decrypted_messages}).encode('utf-8'))

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server started on port 12345")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address}")
        client_handler = ClientHandler(client_socket, address)
        client_handler.start()

if __name__ == "__main__":
    start_server()
