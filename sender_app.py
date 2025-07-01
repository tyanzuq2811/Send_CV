import json
import base64
import os
from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sender-secret-key'
UPLOAD_FOLDER = 'D:\\ATBMTT\\BTL\\BTL2\\input'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_keys():
    try:
        if not os.path.exists("public_key.pem") or not os.path.exists("private_key.pem"):
            raise FileNotFoundError("Missing public_key.pem or private_key.pem. Run generate_keys.py first.")
        public_key = RSA.import_key(open("public_key.pem").read())
        private_key = RSA.import_key(open("private_key.pem").read())
        return public_key, private_key
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1)

public_key, private_key = load_keys()

def pad(data):
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length] * padding_length)
    return data + padding

@app.route('/', methods=['GET'])
def index():
    return render_template('sender.html')

@app.route('/send_cv', methods=['POST'])
def send_cv():
    if 'cv_file' not in request.files or 'sender_ip' not in request.form:
        return jsonify({"message": "Missing file or sender IP", "category": "error"}), 400

    file = request.files['cv_file']
    sender_ip = request.form['sender_ip']

    if file.filename == '':
        return jsonify({"message": "No file selected", "category": "error"}), 400

    try:
        print(f"Handshake: Sender sends Hello! with IP {sender_ip}")
        handshake_url = 'http://127.0.0.1:5001/handshake'
        response = requests.post(handshake_url, data={'sender_ip': sender_ip}, timeout=5)
        if response.status_code != 200 or response.text != "Ready!":
            return jsonify({
                "message": f"NACK: Handshake failed - {response.text} (Status: {response.status_code})",
                "category": "error"
            }), 400
        print("Handshake: Receiver responds Ready!")

        cv_data = file.read()
        if not cv_data:
            return jsonify({"message": "File is empty", "category": "error"}), 400

        timestamp = str(datetime.now().timestamp())
        filename = secure_filename(file.filename)
        metadata = f"{filename}|{timestamp}|{sender_ip}".encode()
        hash_obj = SHA512.new(metadata)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        session_key = os.urandom(16)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        iv = os.urandom(16)
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data = pad(cv_data)
        ciphertext = cipher_aes.encrypt(padded_data)
        hash_input = iv + ciphertext
        file_hash = SHA512.new(hash_input).hexdigest()

        packet = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "hash": file_hash,
            "sig": base64.b64encode(signature).decode(),
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
            "timestamp": timestamp
        }

        receiver_url = 'http://127.0.0.1:5001/receive'
        files = {'cv_file': (file.filename, cv_data, 'application/pdf')}
        data = {'sender_ip': sender_ip, 'packet': json.dumps(packet)}
        response = requests.post(receiver_url, files=files, data=data, timeout=5)

        return jsonify({
            "message": response.text,
            "category": 'info' if 'ACK' in response.text else 'error'
        }), 200 if 'ACK' in response.text else 400

    except requests.exceptions.RequestException as e:
        return jsonify({
            "message": f"Error: Connection to Receiver failed - {str(e)}",
            "category": "error"
        }), 400
    except Exception as e:
        return jsonify({
            "message": f"Error: {str(e)}",
            "category": "error"
        }), 400

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)