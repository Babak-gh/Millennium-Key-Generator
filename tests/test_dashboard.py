import datetime
import unittest

from app import License, Issuer, User, ZigbeeLicense, app, db


class DashboardTest(unittest.TestCase):
    ISSUER = 'dashboard-test-issuer'
    BASE_CODE = 'dashboard-test-base-device'
    ZIGBEE_CODE = 'dashboard-test-zigbee-device'

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        now = datetime.datetime.now(datetime.timezone.utc)
        with app.app_context():
            ZigbeeLicense.query.filter_by(code=self.ZIGBEE_CODE).delete()
            License.query.filter(
                License.code.in_([self.BASE_CODE, self.ZIGBEE_CODE])
            ).delete(synchronize_session=False)
            Issuer.query.filter_by(issuer=self.ISSUER).delete()
            db.session.add(Issuer(
                issuer=self.ISSUER,
                allowed_licenses=3,
                allowed_zigbee_licenses=2,
                created_by='test',
                created_date=now
            ))
            db.session.add(License(
                code=self.BASE_CODE,
                issuer=self.ISSUER,
                owner='Dashboard Base-only Owner',
                project='Dashboard Project',
                is_active=True,
                created_date=now,
                license='dashboard-base-license'
            ))
            db.session.add(License(
                code=self.ZIGBEE_CODE,
                issuer=self.ISSUER,
                owner='Dashboard Full Owner',
                project='Dashboard Project',
                is_active=True,
                created_date=now,
                license='dashboard-full-base-license'
            ))
            db.session.add(ZigbeeLicense(
                license_id='dashboard-test-license-id',
                code=self.ZIGBEE_CODE,
                coordinator_eui64='00124B0000D45B00',
                issuer=self.ISSUER,
                owner='Dashboard Full Owner',
                project='Dashboard Project',
                is_active=True,
                created_date=now,
                license='dashboard-zigbee-license'
            ))
            db.session.commit()

            admin = User.query.filter_by(username='admin').one()
            self.admin_id = admin.id

    def tearDown(self):
        with app.app_context():
            ZigbeeLicense.query.filter_by(code=self.ZIGBEE_CODE).delete()
            License.query.filter(
                License.code.in_([self.BASE_CODE, self.ZIGBEE_CODE])
            ).delete(synchronize_session=False)
            Issuer.query.filter_by(issuer=self.ISSUER).delete()
            db.session.commit()

    def test_dashboard_is_authenticated_and_renders_metrics(self):
        anonymous = self.client.get('/admin/')
        self.assertEqual(anonymous.status_code, 302)
        self.assertIn('/login', anonymous.headers['Location'])

        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.admin_id)
            session['_fresh'] = True

        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('Licensing Dashboard', page)
        self.assertIn('Base licenses created over time', page)
        self.assertIn('Zigbee licenses created over time', page)
        self.assertIn('Issuers created over time', page)
        self.assertIn('Dashboard Full Owner', page)
        self.assertIn('Full / Base / Zigbee', page)

        searchable_pages = [
            '/admin/license/?search=dashboard-test',
            '/admin/zigbeelicense/?search=dashboard-test',
            '/admin/issuer/?search=dashboard-test',
            '/admin/zigbee_requests/?q=dashboard-test&status=all'
        ]
        for url in searchable_pages:
            search_response = self.client.get(url)
            self.assertEqual(search_response.status_code, 200, url)
        request_page = self.client.get('/admin/zigbee_requests/')
        self.assertIn(
            'Choose the billing issuer', request_page.get_data(as_text=True)
        )


if __name__ == '__main__':
    unittest.main()
