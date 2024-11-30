from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import base64
from Crypto import Random
from Crypto.Cipher import AES

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.secret_key = 'your_secret_key_here'

socketio = SocketIO(app, cors_allowed_origins="*")  # Enable WebSocket
DB_PATH = "database.db"
UPLOAD_FOLDER = "./uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Database
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                filename TEXT,
                filepath TEXT,
                accepted BOOLEAN DEFAULT 0
            )
        """)
        conn.commit()

init_db()

# Encryption Utility
class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, plaintext):
        plaintext = self.pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = iv + cipher.encrypt(plaintext)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

# Use a predefined key (should be securely shared)
key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
encryptor = Encryptor(key)

# Encrypt API
@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    data = request.json
    plaintext = data.get('content', '').encode()
    encrypted = encryptor.encrypt(plaintext)
    return jsonify({'encryptedContent': encrypted})

# Decrypt API
@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    data = request.json
    ciphertext = data.get('encryptedContent', '')
    decrypted = encryptor.decrypt(ciphertext)
    return jsonify({'decryptedContent': decrypted.decode()})


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get("username")
    password = generate_password_hash(data.get("password"))

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            return jsonify({"message": "Signup successful"}), 200
        except sqlite3.IntegrityError:
            return jsonify({"message": "Username already exists"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and check_password_hash(result[0], password):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 400

socket_user_map = {}

# Handle WebSocket connections
@socketio.on('join')
def on_join(data):
    username = data['username']
    socket_user_map[request.sid] = username 
    join_room("shared-room")  # All users join a shared room
    
    emit('user_joined', {'username': username}, room="shared-room", skip_sid=request.sid)
   
    print(f"{username} joined the shared room.")

@socketio.on('disconnect')
def on_disconnect():
    # Remove the user from the map when they disconnect
    username = socket_user_map.pop(request.sid, None)
    print(f"{username} disconnected.")

@socketio.on('send_request')
def handle_send_request(data):
    try:
        sender = data['sender']
        receiver = data['receiver']
        filename = data['filename']
        encrypted_content = data['encryptedContent']

        receiver_sid = None
        for sid, user in socket_user_map.items():
            if user == receiver:
             receiver_sid = sid
             break

        if receiver_sid:
        # Send the event to the receiver only
         emit('request_received', {'sender': sender, 'filename': filename, 'encryptedContent': encrypted_content}, to=receiver_sid)
         print(f"File request sent to {receiver}.")
        else:
         print(f"Receiver {receiver} not found.")

    except Exception as e:
        print(f"Error in file_request handler: {e}")


@socketio.on('reject_request')
def handle_reject_request(data):
    print(f"rejected called")
    try:
        sender = data['sender']
        receiver = data['receiver']
        filename = data['filename']

        receiver_sid = None
        for sid, user in socket_user_map.items():
            if user == receiver:
             receiver_sid = sid
             break

        if receiver_sid:
        # Send the event to the receiver only
         emit('request_rejected', {'sender': sender, 'filename': filename, 'msg': "Request rejected"}, to=receiver_sid)
         print(f"File request sent to {receiver}.")
        else:
         print(f"Receiver {receiver} not found.")

    except Exception as e:
        print(f"Error in file_request handler: {e}")


@socketio.on('accept_request')
def handle_accept_request(data):
    try:
        sender = data['sender']
        receiver = data['receiver']
        filename = data['filename']

        receiver_sid = None
        for sid, user in socket_user_map.items():
            if user == receiver:
             receiver_sid = sid
             break

        if receiver_sid:
        # Send the event to the receiver only
         emit('request_accepted', {'sender': sender, 'filename': filename, 'msg': "Request accepted"}, to=receiver_sid)
         print(f"File request sent to {receiver}.")
        else:
         print(f"Receiver {receiver} not found.")

    except Exception as e:
        print(f"Error in file_request handler: {e}")

if __name__ == "__main__":
    socketio.run(app, debug=True)
