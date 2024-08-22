from flask import Flask, jsonify, request
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
import base64
import logging
import os
import jwt
import datetime

app = Flask(__name__)



JWT_SECRET = 'Babak2324723'
JWT_ALGORITHM = 'HS256' 

private_key = RSA.generate(2048)
public_key = private_key.publickey()

def token_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 403
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid Token'}), 403
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/register_device', methods=['POST'])
def register_device():
    data = request.json
    code = data.get('code')

    if not code:
        return jsonify({'error': 'Invalid device ID'}), 400

    payload = {
            'device_id': code,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=2)
            }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({'token': token})


@app.route('/public_key', methods=['GET'])
@token_required
def get_public_key():
    public_key_pem = public_key.export_key(format='PEM')
    public_key_base64 = base64.b64encode(public_key_pem).decode('utf-8')
    return jsonify({'public_key':public_key_base64})


@app.route('/is_active',methods=['POST'])
@token_required
def is_active():
    data = request.json
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    code = data.get('code')
    code_exist_query = f"SELECT * FROM licences WHERE code=?"
    cursor.execute(code_exist_query, (code,))
    code_from_db = cursor.fetchall()
    if not code_from_db:
        return jsonify({'result': False})
    if  code_from_db[0][4] == 1:
        return jsonify({'result': True})
    else:
        return jsonify({'result': False})
    
def sign_device_id(device_id: str) -> str:
    h = SHA256.new(device_id.encode('utf_8'))
    signature = PKCS1_v1_5.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

@app.route('/activate', methods=['POST'])
@token_required
def register_activate_request():
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    data = request.json
    code = data.get('code')
    code_exist_query = f"SELECT * FROM licences WHERE code=?"
    cursor.execute(code_exist_query, (code,))
    code_from_db = cursor.fetchall()
    encrypted_text = None
    app.logger.error(code)
    if code_from_db:
        app.logger.error('code exist')
        return jsonify({'error':'Already activated'}), 403
    else:
        app.logger.error('1')
        issuer = data.get('issuer')
        owner = data.get('owner')
        project = data.get('project')
        #license_data = f"LICENSE-{code}-{os.urandom(16).hex()}"
        license_data = f"{code}"
        #encrypted_text = encrypt(license_data)
        encrypted_text = sign_device_id(license_data)
        cursor.execute("INSERT INTO licences (code, issuer, owner, project, is_active, license) VALUES (?,?,?,?,?,?)", (code, issuer, owner, project, True, encrypted_text))
        conn.commit()
        cursor.close()
        app.logger.error('2')
    conn.close
    app.logger.error(encrypted_text)
    return  jsonify({'encrypted_license': encrypted_text})




if __name__ == '__main__':
    app.run(debug=True)
