from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import inspect, text
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import base64
import hashlib
import hmac
import json
import logging
import os
import jwt
import csv
import datetime
import fcntl
import sqlite3
import uuid
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from nbformat import ValidationError
import pandas as pd
import io
from flask import send_file


app = Flask(__name__)

BASE_DATABASE_PATH = os.path.join(app.instance_path, 'my_database.db')
ZIGBEE_DATABASE_PATH = os.path.join(app.instance_path, 'zigbee_licenses.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + BASE_DATABASE_PATH
app.config['SQLALCHEMY_BINDS'] = {
    'zigbee': 'sqlite:///' + ZIGBEE_DATABASE_PATH
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class DashboardAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    @expose('/')
    def index(self):
        return self.render('admin/dashboard.html', **build_dashboard_context())


admin = Admin(
    app,
    name='Millennium Licensing',
    template_mode='bootstrap3',
    index_view=DashboardAdminIndexView()
)

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

def unique_username(form, field):
    if User.query.filter_by(username=field.data).first():
        raise ValidationError('Username already exists. Please choose a different one.')

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
    allowed_licenses = db.Column(db.Integer, default=0)
    allowed_zigbee_licenses = db.Column(db.Integer, nullable=False, default=0)
    created_by = db.Column(db.String(150), nullable=True)
    created_date = db.Column(
        db.DateTime,
        nullable=True,
        default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

class IssuerAdmin(AuthenticatedModelView):
    column_list = [
        'issuer', 'allowed_licenses', 'allowed_zigbee_licenses', 'created_by',
        'created_date'
    ]
    form_columns = ['issuer', 'allowed_licenses', 'allowed_zigbee_licenses']

    def on_model_change(self, form, model, is_created):
        if is_created:
            model.created_by = current_user.username
            model.created_date = datetime.datetime.now(datetime.timezone.utc)
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
    column_list = ['code', 'issuer', 'owner', 'project', 'is_active', 'created_date', 'license']
    form_columns = ['code', 'issuer', 'owner', 'project', 'is_active', 'created_date', 'license']
    can_export = True
    # Use custom template
    list_template = 'admin/license_list.html'

    def render(self, template, **kwargs):
        if template == self.list_template:
            kwargs['export_url'] = url_for('export_licenses_to_excel')
        return super(LicenseAdmin, self).render(template, **kwargs)


class ZigbeeLicense(db.Model):
    __bind_key__ = 'zigbee'
    __tablename__ = 'zigbee_licenses'
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.String(36), nullable=False, unique=True)
    code = db.Column(db.String(80), nullable=False, unique=True)
    coordinator_eui64 = db.Column(db.String(16), nullable=False, unique=True)
    issuer = db.Column(db.String(120), nullable=False)
    owner = db.Column(db.String(120), nullable=False)
    project = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_date = db.Column(db.DateTime, nullable=False)
    license = db.Column(db.Text, nullable=False)


class ZigbeeLicenseAdmin(AdminOnlyModelView):
    column_list = [
        'license_id', 'code', 'coordinator_eui64', 'issuer', 'owner',
        'project', 'is_active', 'created_date', 'license'
    ]
    form_columns = ['is_active']
    can_create = False
    can_delete = False


class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_code = db.Column(db.Integer, nullable=False)
    release_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(datetime.timezone.utc))
    apk_url = db.Column(db.String(255), nullable=False)
    variant = db.Column(db.Text, nullable=True)

class VersionAdmin(AdminOnlyModelView):
    column_list = ['version_code', 'release_date', 'apk_url', 'variant']
    form_columns = ['version_code', 'release_date', 'apk_url', 'variant']


def _as_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _month_start(value):
    return datetime.datetime(value.year, value.month, 1, tzinfo=datetime.timezone.utc)


def _shift_month(value, offset):
    month_index = value.year * 12 + value.month - 1 + offset
    return datetime.datetime(
        month_index // 12,
        month_index % 12 + 1,
        1,
        tzinfo=datetime.timezone.utc
    )


def build_monthly_chart(values, unknown_label=None, month_count=12):
    current_month = _month_start(datetime.datetime.now(datetime.timezone.utc))
    months = [_shift_month(current_month, offset) for offset in range(1 - month_count, 1)]
    counts = {month: 0 for month in months}
    earlier_count = 0
    unknown_count = 0

    for raw_value in values:
        value = _as_utc(raw_value)
        if value is None:
            unknown_count += 1
            continue
        value_month = _month_start(value)
        if value_month < months[0]:
            earlier_count += 1
        elif value_month in counts:
            counts[value_month] += 1

    points = []
    if earlier_count:
        points.append({'label': 'Earlier', 'count': earlier_count})
    if unknown_label and unknown_count:
        points.append({'label': unknown_label, 'count': unknown_count})
    points.extend({
        'label': month.strftime('%b %y'),
        'count': counts[month]
    } for month in months)

    maximum = max((point['count'] for point in points), default=0) or 1
    for point in points:
        point['height'] = max(5, round(point['count'] * 100 / maximum)) \
            if point['count'] else 0
    return points


def build_dashboard_context():
    base_records = License.query.order_by(License.created_date.desc()).all()
    zigbee_records = ZigbeeLicense.query.order_by(ZigbeeLicense.created_date.desc()).all()
    issuer_records = Issuer.query.order_by(Issuer.issuer.asc()).all()

    active_base_codes = {record.code for record in base_records if record.is_active}
    active_zigbee_codes = {record.code for record in zigbee_records if record.is_active}
    full_codes = active_base_codes & active_zigbee_codes

    recent_activity = []
    for record in base_records[:8]:
        recent_activity.append({
            'kind': 'Base',
            'code': record.code,
            'issuer': record.issuer,
            'owner': record.owner,
            'created_date': _as_utc(record.created_date),
            'active': record.is_active
        })
    for record in zigbee_records[:8]:
        recent_activity.append({
            'kind': 'Zigbee',
            'code': record.code,
            'issuer': record.issuer,
            'owner': record.owner,
            'created_date': _as_utc(record.created_date),
            'active': record.is_active
        })
    recent_activity.sort(
        key=lambda item: item['created_date'] or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc
        ),
        reverse=True
    )

    quota_rows = [{
        'issuer': record.issuer,
        'base': max(record.allowed_licenses or 0, 0),
        'zigbee': max(record.allowed_zigbee_licenses or 0, 0)
    } for record in issuer_records]
    quota_rows.sort(key=lambda row: (row['base'] + row['zigbee'], row['issuer'].lower()))

    return {
        'base_chart': build_monthly_chart(
            [record.created_date for record in base_records]
        ),
        'zigbee_chart': build_monthly_chart(
            [record.created_date for record in zigbee_records]
        ),
        'issuer_chart': build_monthly_chart(
            [record.created_date for record in issuer_records],
            unknown_label='Legacy'
        ),
        'base_total': len(base_records),
        'base_active': len(active_base_codes),
        'zigbee_total': len(zigbee_records),
        'zigbee_active': len(active_zigbee_codes),
        'issuer_total': len(issuer_records),
        'full_total': len(full_codes),
        'base_only_total': len(active_base_codes - full_codes),
        'base_quota_remaining': sum(row['base'] for row in quota_rows),
        'zigbee_quota_remaining': sum(row['zigbee'] for row in quota_rows),
        'legacy_issuer_count': sum(
            1 for record in issuer_records if record.created_date is None
        ),
        'recent_activity': recent_activity[:10],
        'quota_rows': quota_rows[:10],
        'generated_at': datetime.datetime.now(datetime.timezone.utc)
    }


admin.add_view(LicenseAdmin(License, db.session))
admin.add_view(ZigbeeLicenseAdmin(ZigbeeLicense, db.session, name='Zigbee Licenses'))
admin.add_view(UserAdmin(User, db.session))
admin.add_view(IssuerAdmin(Issuer, db.session))
admin.add_view(VersionAdmin(Version, db.session))

def migrate_schema():
    """Apply additive schema changes without replacing the existing SQLite data."""
    issuer_columns = {column['name'] for column in inspect(db.engine).get_columns('issuer')}
    if 'allowed_zigbee_licenses' not in issuer_columns:
        with db.engine.begin() as connection:
            connection.execute(text(
                'ALTER TABLE issuer ADD COLUMN '
                'allowed_zigbee_licenses INTEGER NOT NULL DEFAULT 0'
            ))
    if 'created_date' not in issuer_columns:
        with db.engine.begin() as connection:
            connection.execute(text(
                'ALTER TABLE issuer ADD COLUMN created_date DATETIME'
            ))


def backup_database_before_zigbee_migration():
    """Keep one consistent copy of the pre-Zigbee SQLite database."""
    database_path = db.engine.url.database
    if not database_path or not os.path.isfile(database_path):
        return
    backup_path = f'{database_path}.pre_zigbee_migration.bak'
    if os.path.exists(backup_path):
        return
    with sqlite3.connect(database_path) as source, sqlite3.connect(backup_path) as destination:
        source.backup(destination)
    os.chmod(backup_path, 0o600)


def backup_database_before_dashboard_migration():
    """Keep a snapshot before adding issuer creation timestamps."""
    database_path = db.engine.url.database
    if not database_path or not os.path.isfile(database_path):
        return
    backup_path = f'{database_path}.pre_dashboard_migration.bak'
    if os.path.exists(backup_path):
        return
    with sqlite3.connect(database_path) as source, sqlite3.connect(backup_path) as destination:
        source.backup(destination)
    os.chmod(backup_path, 0o600)


with app.app_context():
    backup_database_before_zigbee_migration()
    backup_database_before_dashboard_migration()
    db.create_all()
    migrate_schema()

    if not User.query.first():
        hashed_password = bcrypt.generate_password_hash(os.environ.get('ADMIN_PASS', 'default_pass')).decode('utf-8')
        new_user = User(username='admin', password=hashed_password, is_admin=True) 
        db.session.add(new_user)
        db.session.commit()

def create_jwt_token(code):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        'device_id': code,
        'token_type': 'access',
        'iat': now,
        'exp': now + datetime.timedelta(minutes=60)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def create_refresh_token(code):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        'device_id': code,
        'token_type': 'refresh',
        'iat': now,
        'exp': now + datetime.timedelta(days=20)
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

    return jsonify({
        'jwt_token': jwt_token,
        'refresh_token': refresh_token
    })

@app.route('/refresh-token', methods=['POST'])
def refresh_jwt_token():
    refresh_token = request.json.get('refresh_token')
    try:
        decoded = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Tokens issued before token types were introduced did not contain this
        # claim. Accept those until their existing 20-day lifetime ends, while
        # preventing newly issued access tokens from being used as refresh tokens.
        if decoded.get('token_type') not in (None, 'refresh'):
            return jsonify({'error': 'Invalid refresh token'}), 401
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
    return jsonify({'public_key': public_key_base64})


@app.route('/is_active', methods=['POST'])
@token_required
def is_active():
    data = request.json
    code = data.get('code')
    license_record = License.query.filter_by(code=code).first()
    if not license_record:
        return jsonify({'result': False})
    if license_record.is_active:
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
            return jsonify({'error': 'You are not allowed to get a license'}), 403
        if existing_issuer.allowed_licenses == 0:
            return jsonify({'error': 'You do not have enough licenses'}), 403

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
        return jsonify({'error': 'Already activated'}), 403

    app.logger.error(encrypted_text)
    return jsonify({'encrypted_license': encrypted_text})

def check_code_in_csv(code):
    file_path = '/app/past.csv'
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row:
                csv_code = row[0][:9]
                if code == csv_code:
                    return True

    return False


_zigbee_signing_key = None


def _base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def get_zigbee_signing_key():
    """Load the dedicated persistent Zigbee signing key, creating it once if needed."""
    global _zigbee_signing_key
    if _zigbee_signing_key is not None:
        return _zigbee_signing_key

    configured_path = os.environ.get('ZIGBEE_LICENSE_PRIVATE_KEY_PATH')
    key_path = os.path.abspath(
        configured_path or os.path.join(app.instance_path, 'zigbee_license_private.pem')
    )
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    # The file lock prevents two server workers from creating different keys at startup.
    with open(f'{key_path}.lock', 'a') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        if not os.path.exists(key_path):
            generated_key = RSA.generate(3072)
            temporary_path = f'{key_path}.{os.getpid()}.tmp'
            with open(temporary_path, 'wb') as key_file:
                key_file.write(generated_key.export_key(format='PEM', passphrase=None, pkcs=8))
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, key_path)

        with open(key_path, 'rb') as key_file:
            _zigbee_signing_key = RSA.import_key(key_file.read())

    return _zigbee_signing_key


def zigbee_public_key_response_fields():
    public_der = get_zigbee_signing_key().publickey().export_key(format='DER')
    return {
        'zigbee_public_key': base64.b64encode(public_der).decode('ascii'),
        'zigbee_key_id': hashlib.sha256(public_der).hexdigest()[:16]
    }


def create_zigbee_entitlement(license_id, code, coordinator_eui64, issued_at):
    # SQLite returns stored datetimes without timezone information. They were
    # written as UTC, so restore that context before reissuing an entitlement.
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=datetime.timezone.utc)
    public_fields = zigbee_public_key_response_fields()
    header = {
        'alg': 'RS256',
        'kid': public_fields['zigbee_key_id'],
        'typ': 'JWT'
    }
    payload = {
        'iss': 'millennium-license-service',
        'sub': code,
        'feature': 'zigbee',
        'coordinator_eui64': coordinator_eui64,
        'license_id': license_id,
        'iat': int(issued_at.timestamp()),
        'schema_version': 1
    }
    encoded_header = _base64url(json.dumps(
        header, sort_keys=True, separators=(',', ':')
    ).encode('utf-8'))
    encoded_payload = _base64url(json.dumps(
        payload, sort_keys=True, separators=(',', ':')
    ).encode('utf-8'))
    signed_content = f'{encoded_header}.{encoded_payload}'.encode('ascii')
    signature = PKCS1_v1_5.new(get_zigbee_signing_key()).sign(SHA256.new(signed_content))
    return f'{encoded_header}.{encoded_payload}.{_base64url(signature)}'


def normalize_coordinator_eui64(value):
    normalized = ''.join(character for character in (value or '') if character.isalnum()).upper()
    if len(normalized) != 16 or any(character not in '0123456789ABCDEF' for character in normalized):
        return None
    return normalized


def persist_zigbee_license_with_quota(
    issuer_id,
    license_id,
    code,
    coordinator_eui64,
    issuer_name,
    owner,
    project,
    created_date,
    entitlement
):
    """Debit Base DB quota and insert into the Zigbee DB in one SQLite transaction."""
    connection = sqlite3.connect(BASE_DATABASE_PATH, timeout=30)
    try:
        connection.execute('ATTACH DATABASE ? AS zigbee', (ZIGBEE_DATABASE_PATH,))
        connection.execute('BEGIN IMMEDIATE')
        quota_update = connection.execute(
            'UPDATE issuer '
            'SET allowed_zigbee_licenses = allowed_zigbee_licenses - 1 '
            'WHERE id = ? AND allowed_zigbee_licenses > 0',
            (issuer_id,)
        )
        if quota_update.rowcount != 1:
            connection.rollback()
            return 'no_quota'

        connection.execute(
            'INSERT INTO zigbee.zigbee_licenses '
            '(license_id, code, coordinator_eui64, issuer, owner, project, '
            'is_active, created_date, license) '
            'VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)',
            (
                license_id,
                code,
                coordinator_eui64,
                issuer_name,
                owner,
                project,
                created_date.astimezone(datetime.timezone.utc)
                .replace(tzinfo=None).isoformat(sep=' '),
                entitlement
            )
        )
        connection.commit()
        return 'created'
    except sqlite3.IntegrityError:
        connection.rollback()
        return 'conflict'
    finally:
        connection.close()


def decode_zigbee_device_access_token(code):
    authorization = request.headers.get('Authorization', '').strip()
    if authorization.lower().startswith('bearer '):
        authorization = authorization[7:].strip()
    if not authorization:
        return None, ('Token is missing', 403)
    try:
        claims = jwt.decode(authorization, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None, ('Token has expired', 403)
    except jwt.InvalidTokenError:
        return None, ('Invalid token', 403)
    if claims.get('token_type') != 'access':
        return None, ('An access token is required', 403)
    if not hmac.compare_digest(str(claims.get('device_id', '')), code):
        return None, ('Token does not belong to this device', 403)
    return claims, None


def zigbee_activation_response(zigbee_license, already_licensed):
    response = {
        'zigbee_license': zigbee_license.license,
        'coordinator_eui64': zigbee_license.coordinator_eui64,
        'already_licensed': already_licensed
    }
    response.update(zigbee_public_key_response_fields())
    return jsonify(response)


@app.route('/zigbee/activate', methods=['POST'])
def activate_zigbee_feature():
    data = request.get_json(silent=True) or {}
    code = str(data.get('code') or '').strip()
    coordinator_eui64 = normalize_coordinator_eui64(data.get('coordinator_eui64'))
    base_license_proof = str(data.get('base_license') or '')

    if not code or len(code) > 80:
        return jsonify({'error': 'Invalid device ID'}), 400
    if coordinator_eui64 is None:
        return jsonify({'error': 'Invalid Zigbee coordinator EUI-64'}), 400

    _, token_error = decode_zigbee_device_access_token(code)
    if token_error:
        message, status = token_error
        return jsonify({'error': message}), status

    base_license = License.query.filter_by(code=code, is_active=True).first()
    if base_license is None:
        return jsonify({'error': 'An active Millennium Base license is required'}), 403
    if not base_license_proof or not hmac.compare_digest(base_license.license, base_license_proof):
        return jsonify({'error': 'Base license proof is invalid'}), 403

    existing = ZigbeeLicense.query.filter_by(code=code).first()
    if existing is not None:
        if not existing.is_active:
            return jsonify({'error': 'The Zigbee license has been disabled'}), 403
        if not hmac.compare_digest(existing.coordinator_eui64, coordinator_eui64):
            return jsonify({
                'error': 'This device is licensed to a different Zigbee coordinator'
            }), 409

        # Reissue using the current persistent signing key. This makes reinstall
        # recovery idempotent and does not consume another quota unit.
        existing.license = create_zigbee_entitlement(
            existing.license_id,
            existing.code,
            existing.coordinator_eui64,
            existing.created_date
        )
        db.session.commit()
        return zigbee_activation_response(existing, already_licensed=True)

    issuer = Issuer.query.filter_by(issuer=base_license.issuer).first()
    if issuer is None:
        return jsonify({'error': 'The Base license issuer no longer exists'}), 403

    now = datetime.datetime.now(datetime.timezone.utc)
    license_id = str(uuid.uuid4())
    entitlement = create_zigbee_entitlement(license_id, code, coordinator_eui64, now)
    issuer_id = issuer.id
    issuer_name = base_license.issuer
    owner = base_license.owner
    project = base_license.project

    # End the ORM read transactions before opening the cross-database write.
    db.session.rollback()
    persistence_result = persist_zigbee_license_with_quota(
        issuer_id=issuer_id,
        license_id=license_id,
        code=code,
        coordinator_eui64=coordinator_eui64,
        issuer_name=issuer_name,
        owner=owner,
        project=project,
        created_date=now,
        entitlement=entitlement
    )
    if persistence_result == 'no_quota':
        return jsonify({'error': 'No Zigbee licenses are available for this issuer'}), 403
    if persistence_result == 'conflict':
        # A concurrent duplicate request should get the already-issued license
        # rather than consume a second quota unit.
        existing = ZigbeeLicense.query.filter_by(code=code).first()
        if existing is not None and existing.is_active and hmac.compare_digest(
            existing.coordinator_eui64, coordinator_eui64
        ):
            return zigbee_activation_response(existing, already_licensed=True)
        return jsonify({'error': 'Zigbee activation conflicted with another request'}), 409

    new_license = ZigbeeLicense.query.filter_by(license_id=license_id).one()
    return zigbee_activation_response(new_license, already_licensed=False), 201


@app.route('/admin/license/export_excel')
@login_required
def export_licenses_to_excel():
    # Query all licenses and outerjoin with issuer to get created_by
    results = db.session.query(
        License.code,
        License.issuer,
        License.owner,
        License.project,
        License.is_active,
        License.created_date,
        License.license,
        Issuer.created_by.label('issuer_created_by')
    ).outerjoin(Issuer, License.issuer == Issuer.issuer).all()

    # Convert to list of dicts for pandas
    data = []
    for row in results:
        data.append({
            'License Code': row.code,
            'Issuer': row.issuer,
            'Owner': row.owner,
            'Project': row.project,
            'Is Active': 'Yes' if row.is_active else 'No',
            'Created Date': row.created_date.strftime('%Y-%m-%d %H:%M:%S') if row.created_date else '',
            'License Data': row.license,
            'Issuer Created By': row.issuer_created_by or 'None'
        })

    # Create DataFrame
    df = pd.DataFrame(data)

    # Write to Excel in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Licenses')

    output.seek(0)

    # Return as downloadable file
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"licenses_export_{now}.xlsx"
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


### Update Android APIs ###

@app.route('/check_update', methods=['POST'])
def check_update():
    variant = request.json.get('variant')
    version_code = request.json.get('version_code')

    latest_version = Version.query.filter_by(variant=variant).order_by(Version.id.desc()).first()
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
    latest_version = Version.query.filter_by(variant=variant).order_by(Version.id.desc()).first()
    if latest_version:
        return redirect(latest_version.apk_url)
    return jsonify({'error': 'No APK available'}), 404

@app.route('/webhook/github/release', methods=['POST'])
def github_release_webhook():
    # 1. Security Check: Ensure only our GitHub Actions can trigger this
    webhook_secret = request.headers.get('X-Webhook-Secret')
    expected_secret = os.environ.get('WEBHOOK_SECRET', 'my_super_secret_webhook_password_123')

    if not webhook_secret or webhook_secret != expected_secret:
        app.logger.warning("Unauthorized webhook attempt.")
        return jsonify({'error': 'Unauthorized'}), 401

    # 2. Parse the payload from GitHub
    data = request.json
    version_code = data.get('version_code')
    releases = data.get('releases') # Expected format: {"basic": "url", "pro": "url", "pro7": "url"}

    if not version_code or not releases:
        return jsonify({'error': 'Invalid payload data'}), 400

    # 3. Update the Database Safely
    try:
        for variant, apk_url in releases.items():
            new_version = Version(
                version_code=int(version_code),
                apk_url=apk_url,
                variant=variant
            )
            db.session.add(new_version)

        db.session.commit()
        app.logger.info(f"Successfully added Version Code {version_code} for variants: {list(releases.keys())}")
        return jsonify({'message': 'Database updated successfully'}), 200

    except Exception as e:
        db.session.rollback() # Abort the transaction if anything fails
        app.logger.error(f"Database error during webhook: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)
