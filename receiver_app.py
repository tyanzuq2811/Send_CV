import json
import base64
import sqlite3
import os
from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from flask import Flask, request, render_template, flash, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'receiver-secret-key'
UPLOAD_FOLDER = 'D:\\ATBMTT\\BTL\\BTL2\\uploads'
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

def init_db():
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS allowed_ips (
            ip_address TEXT PRIMARY KEY,
            candidate_id TEXT,
            created_at DATETIME,
            expires_at DATETIME
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS received_files (
            file_name TEXT,
            sender_ip TEXT,
            received_at DATETIME,
            status TEXT,
            file_size INTEGER
        )
    ''')
    cursor.execute("PRAGMA table_info(received_files)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'file_size' not in columns:
        cursor.execute("ALTER TABLE received_files ADD COLUMN file_size INTEGER")
    cursor.execute("INSERT OR IGNORE INTO allowed_ips (ip_address, candidate_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                   ("192.168.1.100", "candidate_001", "2025-05-25 12:00:00", "2025-12-31 23:59:59"))
    conn.commit()
    conn.close()

def verify_ip(sender_ip):
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM allowed_ips WHERE ip_address = ? AND (expires_at > ? OR expires_at IS NULL)",
                  (sender_ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_unique_filename(filename, upload_folder):
    base, extension = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(upload_folder, new_filename)):
        new_filename = f"{base}_{counter}{extension}"
        counter += 1
    return new_filename

def log_file(file_name, sender_ip, status, file_size=None):
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO received_files (file_name, sender_ip, received_at, status, file_size) VALUES (?, ?, ?, ?, ?)",
                   (file_name, sender_ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status, file_size))
    conn.commit()
    conn.close()

def update_file_status(file_name, new_status):
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE received_files SET status = ? WHERE file_name = ?", (new_status, file_name))
    conn.commit()
    conn.close()

def delete_file(file_name):
    print(f"Attempting to delete file: {file_name}")  
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM received_files WHERE file_name = ?", (file_name,))
    if cursor.rowcount == 0:
        print(f"No record found for file: {file_name}")
    conn.commit()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"File deleted from disk: {file_path}")
    else:
        print(f"File not found on disk: {file_path}")
    conn.close()

def delete_all_files():
    print("Attempting to delete all files")
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("SELECT file_name FROM received_files")
    files = cursor.fetchall()
    cursor.execute("DELETE FROM received_files")
    conn.commit()
    for file_name in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name[0])
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"File deleted from disk: {file_path}")
        else:
            print(f"File not found on disk: {file_path}")
    conn.close()

def pad(data):
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

@app.route('/handshake', methods=['POST'])
def handshake():
    init_db()
    sender_ip = request.form.get('sender_ip')
    if not sender_ip:
        return "NACK: No IP provided", 400
    print(f"Handshake: Receiver checks IP {sender_ip}")
    if verify_ip(sender_ip):
        print("Handshake: Receiver responds Ready!")
        return "Ready!", 200
    else:
        log_file("unknown.pdf", sender_ip, "failed: Invalid IP", 0)
        return "NACK: Invalid IP", 400

@app.route('/receive', methods=['POST'])
def receive_cv():
    init_db()
    if 'cv_file' not in request.files or 'sender_ip' not in request.form or 'packet' not in request.form:
        return "NACK: Missing data", 400

    file = request.files['cv_file']
    sender_ip = request.form['sender_ip']
    packet = json.loads(request.form['packet'])

    if file.filename == '':
        return "NACK: No file selected", 400

    try:    
        cv_data = file.read()
        file_size = len(cv_data)

        original_filename = secure_filename(file.filename)
        unique_filename = get_unique_filename(original_filename, app.config['UPLOAD_FOLDER'])

        iv = base64.b64decode(packet["iv"])
        ciphertext = base64.b64decode(packet["cipher"])
        file_hash = packet["hash"]
        signature = base64.b64decode(packet["sig"])
        encrypted_session_key = base64.b64decode(packet["encrypted_session_key"])
        timestamp = packet["timestamp"]
        metadata = f"{original_filename}|{timestamp}|{sender_ip}".encode()
        hash_obj = SHA512.new(metadata)

        print(f"Received signature: {signature}")
        print(f"Reconstructed metadata: {metadata.decode()}")
        try:
            pkcs1_15.new(public_key).verify(hash_obj, signature)
        except Exception as e:
            log_file(original_filename, sender_ip, f"failed: Invalid signature - {str(e)}", file_size)
            return "NACK: Invalid signature", 400

        hash_input = iv + ciphertext
        computed_hash = SHA512.new(hash_input).hexdigest()
        if computed_hash != file_hash:
            log_file(original_filename, sender_ip, "failed: Integrity check failed", file_size)
            return "NACK: Integrity check failed", 400

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data = cipher_aes.decrypt(ciphertext)
        cv_data = unpad(padded_data)

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        with open(output_path, "wb") as f:
            f.write(cv_data)

        log_file(unique_filename, sender_ip, "success", file_size)
        return "ACK: File received successfully", 200

    except Exception as e:
        return f"NACK: Error - {str(e)}", 400

@app.route('/get_files', methods=['GET'])
def get_files():
    init_db()
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("SELECT file_name, sender_ip, received_at, status, file_size FROM received_files ORDER BY received_at DESC")
    files = cursor.fetchall()
    conn.close()
    files_data = [
        {"file_name": file[0], "sender_ip": file[1], "received_at": file[2], "status": file[3], "file_size": file[4]}
        for file in files
    ]
    return jsonify(files_data)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    init_db()
    conn = sqlite3.connect("recruitment.db")
    cursor = conn.cursor()
    cursor.execute("SELECT file_name, sender_ip, received_at, status, file_size FROM received_files ORDER BY received_at DESC")
    files = cursor.fetchall()
    conn.close()
    return render_template('receiver.html', files=files)

@app.route('/update_status', methods=['POST'])
def update_status():
    data = request.json
    file_name = data.get('file_name')
    new_status = data.get('status')
    if file_name and new_status:
        update_file_status(file_name, new_status)
        return jsonify({"message": "Status updated successfully"}), 200
    return jsonify({"message": "Invalid data"}), 400

@app.route('/delete_file', methods=['POST'])
def delete_file_route():
    data = request.json
    file_name = data.get('file_name')
    if file_name:
        try:
            delete_file(file_name)
            return jsonify({"message": "File deleted successfully"}), 200
        except Exception as e:
            return jsonify({"message": f"Error deleting file: {str(e)}"}), 500
    return jsonify({"message": "Invalid data"}), 400

@app.route('/delete_all_files', methods=['POST'])
def delete_all_files_route():
    try:
        delete_all_files()
        return jsonify({"message": "All files deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Error deleting all files: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)