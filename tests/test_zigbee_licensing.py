import base64
import datetime
import json
import unittest

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from app import (
    License, Issuer, ZigbeeLicense, ZigbeeLicenseRequest,
    app, approve_zigbee_license_request, db
)


class ZigbeeLicensingTest(unittest.TestCase):
    DEVICE_CODE = 'zigbee-upgrade-test-device'
    FULL_CODE = 'zigbee-full-test-device'
    ZIGBEE_ONLY_CODE = 'zigbee-only-test-device'
    COORDINATOR = '00124B0001ABCDEF'
    FULL_COORDINATOR = '00124B0001ABCDE0'
    ZIGBEE_ONLY_COORDINATOR = '00124B0001ABCDE1'
    BASE_ISSUER = 'historical-base-test-issuer'
    BILLING_ISSUER = 'zigbee-billing-test-issuer'
    PRODUCT_ISSUER = 'new-product-test-issuer'
    BASE_PROOF = 'zigbee-license-test-base-proof'

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.codes = [self.DEVICE_CODE, self.FULL_CODE, self.ZIGBEE_ONLY_CODE]
        with app.app_context():
            self._delete_test_data()
            db.session.add_all([
                Issuer(
                    issuer=self.BASE_ISSUER, allowed_licenses=0,
                    allowed_zigbee_licenses=0, created_by='test'
                ),
                Issuer(
                    issuer=self.BILLING_ISSUER, allowed_licenses=0,
                    allowed_zigbee_licenses=1, created_by='test'
                ),
                Issuer(
                    issuer=self.PRODUCT_ISSUER, allowed_licenses=1,
                    allowed_zigbee_licenses=2, created_by='test'
                )
            ])
            db.session.add(License(
                code=self.DEVICE_CODE,
                issuer=self.BASE_ISSUER,
                owner='Existing Customer',
                project='Legacy Project',
                is_active=True,
                created_date=datetime.datetime.now(datetime.timezone.utc),
                license=self.BASE_PROOF
            ))
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            self._delete_test_data()
            db.session.commit()

    def _delete_test_data(self):
        ZigbeeLicenseRequest.query.filter(
            ZigbeeLicenseRequest.code.in_(self.codes)
        ).delete(synchronize_session=False)
        ZigbeeLicense.query.filter(
            ZigbeeLicense.code.in_(self.codes)
        ).delete(synchronize_session=False)
        License.query.filter(License.code.in_(self.codes)).delete(
            synchronize_session=False
        )
        Issuer.query.filter(Issuer.issuer.in_([
            self.BASE_ISSUER, self.BILLING_ISSUER, self.PRODUCT_ISSUER
        ])).delete(synchronize_session=False)

    def access_token(self, code):
        response = self.client.post('/register_device', json={'code': code})
        self.assertEqual(response.status_code, 200)
        return response.get_json()['jwt_token']

    def test_existing_base_upgrade_waits_for_explicit_billing_issuer(self):
        response = self.client.post(
            '/zigbee/request',
            headers={'Authorization': self.access_token(self.DEVICE_CODE)},
            json={
                'code': self.DEVICE_CODE,
                'coordinator_eui64': self.COORDINATOR,
                'base_license': self.BASE_PROOF
            }
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()['status'], 'pending')

        legacy_pending = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': self.access_token(self.DEVICE_CODE)},
            json={
                'code': self.DEVICE_CODE,
                'coordinator_eui64': self.COORDINATOR,
                'base_license': self.BASE_PROOF
            }
        )
        self.assertEqual(legacy_pending.status_code, 409)
        self.assertIn('waiting', legacy_pending.get_json()['error'])

        with app.app_context():
            pending = ZigbeeLicenseRequest.query.filter_by(
                code=self.DEVICE_CODE
            ).one()
            self.assertEqual(pending.base_issuer, self.BASE_ISSUER)
            self.assertIsNone(pending.billing_issuer)
            billing = Issuer.query.filter_by(issuer=self.BILLING_ISSUER).one()
            self.assertEqual(billing.allowed_zigbee_licenses, 1)

            result, _ = approve_zigbee_license_request(
                pending.id, billing.id, 'admin-test'
            )
            self.assertEqual(result, 'approved')
            db.session.expire_all()
            approved = ZigbeeLicenseRequest.query.filter_by(
                code=self.DEVICE_CODE
            ).one()
            issued = ZigbeeLicense.query.filter_by(code=self.DEVICE_CODE).one()
            billing = Issuer.query.filter_by(issuer=self.BILLING_ISSUER).one()
            self.assertEqual(approved.status, 'approved')
            self.assertEqual(approved.billing_issuer, self.BILLING_ISSUER)
            self.assertEqual(issued.base_issuer, self.BASE_ISSUER)
            self.assertEqual(issued.issuer, self.BILLING_ISSUER)
            self.assertEqual(issued.license_type, 'addon')
            self.assertEqual(billing.allowed_zigbee_licenses, 0)

        restored = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': self.access_token(self.DEVICE_CODE)},
            json={
                'code': self.DEVICE_CODE,
                'coordinator_eui64': self.COORDINATOR,
                'base_license': self.BASE_PROOF
            }
        )
        self.assertEqual(restored.status_code, 200)
        body = restored.get_json()
        self.assertEqual(body['status'], 'approved')
        self.assertTrue(body['already_licensed'])
        self.assert_entitlement(body, 'addon')

    def test_full_and_zigbee_only_products_consume_the_correct_quotas(self):
        full = self.activate_product(
            self.FULL_CODE, self.FULL_COORDINATOR, 'full'
        )
        self.assertEqual(full.status_code, 201)
        self.assertIsNotNone(full.get_json()['encrypted_license'])
        self.assert_entitlement(full.get_json(), 'full')

        zigbee_only = self.activate_product(
            self.ZIGBEE_ONLY_CODE, self.ZIGBEE_ONLY_COORDINATOR, 'zigbee_only'
        )
        self.assertEqual(zigbee_only.status_code, 201)
        self.assertIsNone(zigbee_only.get_json()['encrypted_license'])
        self.assert_entitlement(zigbee_only.get_json(), 'zigbee_only')

        with app.app_context():
            issuer = Issuer.query.filter_by(issuer=self.PRODUCT_ISSUER).one()
            self.assertEqual(issuer.allowed_licenses, 0)
            self.assertEqual(issuer.allowed_zigbee_licenses, 0)
            self.assertIsNotNone(License.query.filter_by(code=self.FULL_CODE).first())
            self.assertIsNone(License.query.filter_by(code=self.ZIGBEE_ONLY_CODE).first())
            zigbee_only_record = ZigbeeLicense.query.filter_by(
                code=self.ZIGBEE_ONLY_CODE
            ).one()
            self.assertEqual(zigbee_only_record.license_type, 'zigbee_only')
            self.assertIsNone(zigbee_only_record.base_issuer)

        restored = self.activate_product(
            self.ZIGBEE_ONLY_CODE, self.ZIGBEE_ONLY_COORDINATOR, 'zigbee_only'
        )
        self.assertEqual(restored.status_code, 200)
        self.assertTrue(restored.get_json()['already_licensed'])

    def activate_product(self, code, coordinator, license_type):
        return self.client.post(
            '/activate',
            headers={'Authorization': self.access_token(code)},
            json={
                'code': code,
                'coordinator_eui64': coordinator,
                'issuer': self.PRODUCT_ISSUER,
                'owner': 'New Customer',
                'project': 'New Project',
                'new': True,
                'license_type': license_type
            }
        )

    def assert_entitlement(self, body, expected_license_type):
        entitlement = body['zigbee_license']
        header, payload, signature = entitlement.split('.')
        signed_content = f'{header}.{payload}'.encode('ascii')
        signature_bytes = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
        public_key = RSA.import_key(base64.b64decode(body['zigbee_public_key']))
        self.assertTrue(PKCS1_v1_5.new(public_key).verify(
            SHA256.new(signed_content), signature_bytes
        ))
        payload_json = json.loads(base64.urlsafe_b64decode(
            payload + '=' * (-len(payload) % 4)
        ))
        self.assertEqual(payload_json['license_type'], expected_license_type)


if __name__ == '__main__':
    unittest.main()
