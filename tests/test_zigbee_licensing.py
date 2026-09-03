import base64
import datetime
import unittest

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from app import License, Issuer, ZigbeeLicense, app, db


class ZigbeeLicensingTest(unittest.TestCase):
    DEVICE_CODE = 'zigbee-license-test-device'
    OTHER_DEVICE_CODE = 'zigbee-license-test-other-device'
    COORDINATOR = '00124B0001ABCDEF'
    OTHER_COORDINATOR = '00124B0001ABCDE0'
    ISSUER = 'zigbee-license-test-issuer'
    BASE_PROOF = 'zigbee-license-test-base-proof'
    OTHER_BASE_PROOF = 'zigbee-license-test-other-base-proof'

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        with app.app_context():
            ZigbeeLicense.query.filter(
                ZigbeeLicense.code.in_([self.DEVICE_CODE, self.OTHER_DEVICE_CODE])
            ).delete(synchronize_session=False)
            License.query.filter(
                License.code.in_([self.DEVICE_CODE, self.OTHER_DEVICE_CODE])
            ).delete(synchronize_session=False)
            Issuer.query.filter_by(issuer=self.ISSUER).delete(synchronize_session=False)
            db.session.add(Issuer(
                issuer=self.ISSUER,
                allowed_licenses=0,
                allowed_zigbee_licenses=1,
                created_by='test'
            ))
            db.session.add(License(
                code=self.DEVICE_CODE,
                issuer=self.ISSUER,
                owner='Test Owner',
                project='Test Project',
                is_active=True,
                created_date=datetime.datetime.now(datetime.timezone.utc),
                license=self.BASE_PROOF
            ))
            db.session.add(License(
                code=self.OTHER_DEVICE_CODE,
                issuer=self.ISSUER,
                owner='Base-only Owner',
                project='Base-only Project',
                is_active=True,
                created_date=datetime.datetime.now(datetime.timezone.utc),
                license=self.OTHER_BASE_PROOF
            ))
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            ZigbeeLicense.query.filter(
                ZigbeeLicense.code.in_([self.DEVICE_CODE, self.OTHER_DEVICE_CODE])
            ).delete(synchronize_session=False)
            License.query.filter(
                License.code.in_([self.DEVICE_CODE, self.OTHER_DEVICE_CODE])
            ).delete(synchronize_session=False)
            Issuer.query.filter_by(issuer=self.ISSUER).delete(synchronize_session=False)
            db.session.commit()

    def access_token(self, code=None):
        response = self.client.post('/register_device', json={
            'code': code or self.DEVICE_CODE
        })
        self.assertEqual(response.status_code, 200)
        return response.get_json()['jwt_token']

    def activation_body(self, coordinator=None):
        return {
            'code': self.DEVICE_CODE,
            'coordinator_eui64': coordinator or self.COORDINATOR,
            'base_license': self.BASE_PROOF
        }

    def test_activation_is_device_bound_signed_and_idempotent(self):
        wrong_token_response = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': self.access_token(self.OTHER_DEVICE_CODE)},
            json=self.activation_body()
        )
        self.assertEqual(wrong_token_response.status_code, 403)

        token = self.access_token()
        response = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': token},
            json=self.activation_body()
        )
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertFalse(body['already_licensed'])
        self.assertEqual(body['coordinator_eui64'], self.COORDINATOR)
        self.assert_entitlement_signature_is_valid(
            body['zigbee_license'], body['zigbee_public_key']
        )

        with app.app_context():
            issuer = Issuer.query.filter_by(issuer=self.ISSUER).one()
            self.assertEqual(issuer.allowed_zigbee_licenses, 0)
            self.assertEqual(ZigbeeLicense.query.filter_by(code=self.DEVICE_CODE).count(), 1)

        repeat = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': self.access_token()},
            json=self.activation_body()
        )
        self.assertEqual(repeat.status_code, 200)
        self.assertTrue(repeat.get_json()['already_licensed'])
        with app.app_context():
            issuer = Issuer.query.filter_by(issuer=self.ISSUER).one()
            self.assertEqual(issuer.allowed_zigbee_licenses, 0)

        swapped_coordinator = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': self.access_token()},
            json=self.activation_body(self.OTHER_COORDINATOR)
        )
        self.assertEqual(swapped_coordinator.status_code, 409)

        base_only = self.client.post(
            '/zigbee/activate',
            headers={'Authorization': self.access_token(self.OTHER_DEVICE_CODE)},
            json={
                'code': self.OTHER_DEVICE_CODE,
                'coordinator_eui64': self.OTHER_COORDINATOR,
                'base_license': self.OTHER_BASE_PROOF
            }
        )
        self.assertEqual(base_only.status_code, 403)
        self.assertIn('No Zigbee licenses', base_only.get_json()['error'])
        with app.app_context():
            self.assertEqual(
                ZigbeeLicense.query.filter_by(code=self.OTHER_DEVICE_CODE).count(),
                0
            )

    def assert_entitlement_signature_is_valid(self, entitlement, public_key_base64):
        header, payload, signature = entitlement.split('.')
        signed_content = f'{header}.{payload}'.encode('ascii')
        signature_bytes = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
        public_key = RSA.import_key(base64.b64decode(public_key_base64))
        verified = PKCS1_v1_5.new(public_key).verify(
            SHA256.new(signed_content), signature_bytes
        )
        self.assertTrue(verified)


if __name__ == '__main__':
    unittest.main()
