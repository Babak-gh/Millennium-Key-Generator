"""Verify that importing the upgraded app preserves a pre-Zigbee database.

Run this script in an isolated copy of the project. It intentionally creates an
``instance/my_database.db`` fixture before importing ``app``.
"""

import os
import sqlite3
import sys


database_path = os.path.abspath('instance/my_database.db')
zigbee_database_path = os.path.abspath('instance/zigbee_licenses.db')
backup_path = f'{database_path}.pre_zigbee_migration.bak'
dashboard_backup_path = f'{database_path}.pre_dashboard_migration.bak'
zigbee_workflow_backup_path = f'{zigbee_database_path}.pre_workflow_migration.bak'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.makedirs(os.path.dirname(database_path), exist_ok=True)

for path in (
    database_path, zigbee_database_path, backup_path, dashboard_backup_path,
    zigbee_workflow_backup_path
):
    if os.path.exists(path):
        os.remove(path)

with sqlite3.connect(database_path) as connection:
    connection.execute(
        'CREATE TABLE issuer ('
        'id INTEGER PRIMARY KEY, '
        'issuer VARCHAR(120) NOT NULL UNIQUE, '
        'allowed_licenses INTEGER DEFAULT 0, '
        'created_by VARCHAR(150)'
        ')'
    )
    connection.execute(
        'INSERT INTO issuer '
        '(id, issuer, allowed_licenses, created_by) '
        "VALUES (42, 'migration-test-issuer', 17, 'migration-test-user')"
    )
    connection.commit()

with sqlite3.connect(zigbee_database_path) as connection:
    connection.execute(
        'CREATE TABLE zigbee_licenses ('
        'id INTEGER PRIMARY KEY, '
        'license_id VARCHAR(36) NOT NULL UNIQUE, '
        'code VARCHAR(80) NOT NULL UNIQUE, '
        'coordinator_eui64 VARCHAR(16) NOT NULL UNIQUE, '
        'issuer VARCHAR(120) NOT NULL, '
        'owner VARCHAR(120) NOT NULL, '
        'project VARCHAR(120) NOT NULL, '
        'is_active BOOLEAN NOT NULL, '
        'created_date DATETIME NOT NULL, '
        'license TEXT NOT NULL'
        ')'
    )
    connection.execute(
        'INSERT INTO zigbee_licenses '
        '(id, license_id, code, coordinator_eui64, issuer, owner, project, '
        'is_active, created_date, license) VALUES '
        "(7, 'legacy-zigbee-id', 'legacy-device', '00124B0001ABCDEF', "
        "'migration-test-issuer', 'Legacy Owner', 'Legacy Project', 1, "
        "'2026-01-01 00:00:00', 'legacy-entitlement')"
    )
    connection.commit()

# Importing the application runs its normal startup migration.
import app  # noqa: E402


with sqlite3.connect(database_path) as connection:
    columns = {
        row[1] for row in connection.execute('PRAGMA table_info(issuer)').fetchall()
    }
    preserved = connection.execute(
        'SELECT id, issuer, allowed_licenses, allowed_zigbee_licenses, '
        'created_by, created_date '
        'FROM issuer WHERE id = 42'
    ).fetchone()

assert 'allowed_zigbee_licenses' in columns
assert 'created_date' in columns
assert preserved == (42, 'migration-test-issuer', 17, 0, 'migration-test-user', None)
assert os.path.isfile(backup_path)
assert os.path.isfile(dashboard_backup_path)
assert os.path.isfile(zigbee_database_path)

with sqlite3.connect(zigbee_database_path) as connection:
    zigbee_tables = {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    zigbee_columns = {
        row[1] for row in connection.execute(
            'PRAGMA table_info(zigbee_licenses)'
        ).fetchall()
    }
    legacy_zigbee = connection.execute(
        'SELECT id, license_id, code, base_issuer, license_type, license '
        'FROM zigbee_licenses WHERE id = 7'
    ).fetchone()

assert 'zigbee_licenses' in zigbee_tables
assert 'zigbee_license_requests' in zigbee_tables
assert 'base_issuer' in zigbee_columns
assert 'license_type' in zigbee_columns
assert legacy_zigbee == (
    7, 'legacy-zigbee-id', 'legacy-device', None, 'addon',
    'legacy-entitlement'
)
assert os.path.isfile(zigbee_workflow_backup_path)

with sqlite3.connect(zigbee_workflow_backup_path) as connection:
    workflow_backup_columns = {
        row[1] for row in connection.execute(
            'PRAGMA table_info(zigbee_licenses)'
        ).fetchall()
    }
    workflow_backup_row = connection.execute(
        'SELECT id, license_id, code, license FROM zigbee_licenses WHERE id = 7'
    ).fetchone()

assert 'base_issuer' not in workflow_backup_columns
assert 'license_type' not in workflow_backup_columns
assert workflow_backup_row == (
    7, 'legacy-zigbee-id', 'legacy-device', 'legacy-entitlement'
)

with sqlite3.connect(backup_path) as connection:
    backup_columns = {
        row[1] for row in connection.execute('PRAGMA table_info(issuer)').fetchall()
    }
    backup_row = connection.execute(
        'SELECT id, issuer, allowed_licenses, created_by FROM issuer WHERE id = 42'
    ).fetchone()

assert 'allowed_zigbee_licenses' not in backup_columns
assert backup_row == (42, 'migration-test-issuer', 17, 'migration-test-user')

with sqlite3.connect(dashboard_backup_path) as connection:
    dashboard_backup_columns = {
        row[1] for row in connection.execute('PRAGMA table_info(issuer)').fetchall()
    }

assert 'created_date' not in dashboard_backup_columns

print('Legacy Base and Zigbee records survived all additive migrations and backups.')
