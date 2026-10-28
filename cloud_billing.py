"""Cloud coverage reconciliation. Never infer an unpaid debt from a failed lookup."""
import os
from urllib.parse import urlsplit

import requests


class ReconciliationUnavailable(Exception):
    pass


def reconcile_cloud_coverage(licenses):
    token = os.environ.get('LICENSING_SERVICE_TOKEN', '')
    base_url = os.environ.get('CLOUD_LICENSING_URL', '').rstrip('/')
    parsed = urlsplit(base_url)
    if len(token) < 32 or parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise ReconciliationUnavailable('Configure CLOUD_LICENSING_URL and LICENSING_SERVICE_TOKEN first.')
    if parsed.scheme != 'https' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ReconciliationUnavailable('Cloud billing requires HTTPS outside localhost.')
    results = {}
    try:
        for start in range(0, len(licenses), 500):
            batch = licenses[start:start + 500]
            response = requests.post(
                base_url + '/internal/licensing/coverage',
                headers={'Authorization': 'Bearer ' + token},
                json={'licenses': batch}, timeout=(5, 15), allow_redirects=False,
            )
            if response.status_code != 200:
                raise ValueError('Coverage service rejected request')
            rows = response.json()['results']
            if not isinstance(rows, list) or len(rows) != len(batch):
                raise ValueError('Incomplete reconciliation')
            expected = {row['key'] for row in batch}
            if {row['key'] for row in rows} != expected:
                raise ValueError('Mismatched license keys')
            for row in rows:
                if row['status'] not in ('COVERED_BY_CLOUD', 'REVIEW_REQUIRED', 'NOT_COVERED'):
                    raise ValueError('Unknown reconciliation status')
                if row['status'] == 'COVERED_BY_CLOUD' and not all(row.get(key) for key in ('homeId', 'paymentId', 'reference')):
                    raise ValueError('Missing settlement evidence')
                results[row['key']] = row
    except (requests.RequestException, ValueError, KeyError, TypeError) as error:
        raise ReconciliationUnavailable('Cloud reconciliation is unavailable. No collection report was generated; retry later.') from error
    return results


def excel_text(value):
    """Do not allow customer-supplied spreadsheet formulas in a collection export."""
    text = str(value or '')
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text
