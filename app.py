from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import base64
import logging
import os
import jwt
import csv
import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt


app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'my_database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

admin = Admin(app, name='Database Admin', template_mode='bootstrap3')

JWT_SECRET = os.environ.get('JWT_SECRET', 'default_jwt_secret')
JWT_ALGORITHM = 'HS256' 

private_key = RSA.generate(2048)
public_key = private_key.publickey()

class AuthenticatedModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))
    
    
class AdminOnlyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
class UserAdmin(AdminOnlyModelView):
    column_list = ['username', 'password', 'is_admin']
    form_columns = ['username', 'password', 'is_admin']

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Issuer(db.Model):
    __tablename__ = 'issuer'
    id = db.Column(db.Integer, primary_key=True)
    issuer = db.Column(db.String(120), nullable=False, unique=True)
    allowed_licenses = db.Column(db.Integer, default = 0)
    created_by = db.Column(db.String(150), nullable=True)

class IssuerAdmin(AuthenticatedModelView):
    column_list = ['issuer', 'allowed_licenses', 'created_by']
    form_columns = ['issuer', 'allowed_licenses']
    
    def on_model_change(self, form, model, is_created):
        if is_created:
            model.created_by = current_user.username
        super(IssuerAdmin, self).on_model_change(form, model, is_created)


class License(db.Model):
    __tablename__ = 'licences'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(80), nullable=False, unique=True)
    issuer = db.Column(db.String(120), nullable=False)
    owner = db.Column(db.String(120), nullable=False)
    project = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_date = db.Column(db.DateTime, nullable=False)
    license = db.Column(db.String(500), nullable=False)

class LicenseAdmin(AdminOnlyModelView):
    column_list = ['code', 'issuer', 'owner', 'project', 'is_active','created_date', 'license']
    form_columns = ['code', 'issuer', 'owner', 'project', 'is_active','created_date', 'license']


class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_code = db.Column(db.Integer, nullable=False)
    release_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(datetime.timezone.utc))
    apk_url = db.Column(db.String(255), nullable=False)
    variant = db.Column(db.Text, nullable=True)

#class VersionAdmin(ModelView):
 #   column_list = ['id', 'version_code', 'release_date' , 'apk_url' , 'variant']
 #   form_columns = ['id', 'version_code', 'release_date' , 'apk_url' , 'variant']


admin.add_view(LicenseAdmin(License, db.session))
admin.add_view(UserAdmin(User, db.session))
admin.add_view(IssuerAdmin(Issuer, db.session))
admin.add_view(AdminOnlyModelView(Version, db.session))

with app.app_context():
     db.create_all()

     if not User.query.first():
        hashed_password = bcrypt.generate_password_hash(os.environ.get('ADMIN_PASS' , 'default_pass')).decode('utf-8')
        new_user = User(username='admin', password=hashed_password, is_admin=True) 
        db.session.add(new_user)
        db.session.commit()

def create_jwt_token(code):
    payload = {
        'device_id': code,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
        }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def create_refresh_token(code):
    payload = {
        'device_id': code,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=20)
        }
    refresh_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return refresh_token   


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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin.index'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register_device', methods=['POST'])
def register_device():
    data = request.json
    code = data.get('code')

    if not code:
        return jsonify({'error': 'Invalid device ID'}), 400

    jwt_token = create_jwt_token(code)
    refresh_token = create_refresh_token(code)

    return jsonify({'jwt_token': jwt_token,
                    'refresh_token': refresh_token
                    })

@app.route('/refresh-token', methods=['POST'])
def refresh_jwt_token():
    refresh_token = request.json.get('refresh_token')
    try:
        decoded = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        device_id = decoded['device_id']
        new_jwt_token = create_jwt_token(device_id)
        return jsonify({'jwt_token': new_jwt_token}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401


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
    is_new = data.get('new')

    is_manual_license = False
    if not is_new:
        if len(code) >= 9 and check_code_in_csv(code[:9]):
            is_manual_license = True

    existing_license = License.query.filter_by(code=code).first()

    encrypted_text = None
        
    if (not existing_license) or (not existing_license.is_active) or is_manual_license:
        issuer = data.get('issuer')
        existing_issuer = Issuer.query.filter_by(issuer=issuer).first()
        if not existing_issuer:
            return jsonify({'error':'You are not allowed to get a license'}), 403
        if existing_issuer.allowed_licenses == 0:
            return jsonify({'error':'You do not have enough licenses'}), 403
        
        owner = data.get('owner')
        project = data.get('project')
        license_data = f"{code}"
        encrypted_text = sign_device_id(license_data)
        if existing_license:
            existing_license.issuer = issuer
            existing_license.owner = owner
            existing_license.project = project
            existing_license.is_active = True
            existing_license.license = encrypted_text
        else:
            new_license = License(
                code=code, issuer=issuer, owner=owner, project=project,
                is_active=True, license=encrypted_text, created_date=datetime.datetime.now(datetime.timezone.utc)
                )
            db.session.add(new_license)
        existing_issuer.allowed_licenses -= 1
        db.session.commit()
    else:
        return jsonify({'error':'Already activated'}), 403
    
    app.logger.error(encrypted_text)
    return  jsonify({'encrypted_license': encrypted_text})

def check_code_in_csv(code):
    file_path = '/app/past.csv'  # Path to your CSV file in the Docker container
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        
        # Loop through each row in the CSV
        for row in reader:
            if row:  # Make sure the row is not empty
                csv_code = row[0][:9]  # Assuming code is in the first column and taking first 8 characters
                if code == csv_code:
                    return True  # Code found

    return False  # Code not found


### Update Android APIs ###

@app.route('/check_update', methods=['POST'])
def check_update():
    variant = request.json.get('variant')
    version_code = request.json.get('version_code')

    latest_version = Version.query.filter_by(variant = variant).order_by(Version.id.desc()).first()
    if not latest_version:
        return jsonify({'error': 'No version available'}), 404

    if version_code < latest_version.version_code:
        return jsonify({
            'version_code': latest_version.version_code,
            'apk_url': latest_version.apk_url
        }), 200
    else:
        return jsonify({'error': 'You have the latest version'}), 404

@app.route('/download_apk', methods=['GET'])
def download_apk():
    variant = request.args.get('variant')
    latest_version = Version.query.filter_by(variant = variant).order_by(Version.id.desc()).first()
    if latest_version:
        return redirect(latest_version.apk_url)
    return jsonify({'error': 'No APK available'}), 404



if __name__ == '__main__':
    app.run(debug=True)
