from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
admin = Admin(app, name='Database Admin', template_mode='bootstrap3')

JWT_SECRET = 'Babak2324723'
JWT_ALGORITHM = 'HS256' 

private_key = RSA.generate(2048)
public_key = private_key.publickey()

class License(db.Model):
    __tablename__ = 'licences'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(80), nullable=False, unique=True)
    issuer = db.Column(db.String(120), nullable=False)
    owner = db.Column(db.String(120), nullable=False)
    project = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    license = db.Column(db.String(500), nullable=False)

class LicenseAdmin(ModelView):
    column_list = ['code', 'issuer', 'owner', 'project', 'is_active']
    form_columns = ['code', 'issuer', 'owner', 'project', 'is_active', 'license']

admin.add_view(LicenseAdmin(License, db.session))

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
    code = data.get('code')
    license_record = License.query.filter_by(code=code).first()
    if not license_record:
        return jsonify({'result': False})
    if  license_record.is_active:
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
    data = request.json
    code = data.get('code')

    existing_license = License.query.filter_by(code=code).first()

    encrypted_text = None
    #app.logger.error(code)
    if existing_license:
        return jsonify({'error':'Already activated'}), 403
    else:
        issuer = data.get('issuer')
        owner = data.get('owner')
        project = data.get('project')
        #license_data = f"LICENSE-{code}-{os.urandom(16).hex()}"
        license_data = f"{code}"
        #encrypted_text = encrypt(license_data)
        encrypted_text = sign_device_id(license_data)
        new_license = License(
            code=code, issuer=issuer, owner=owner, project=project,
            is_active=True, license=encrypted_text
            )
        db.session.add(new_license)
        db.session.commit()
    
    app.logger.error(encrypted_text)
    return  jsonify({'encrypted_license': encrypted_text})




if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
