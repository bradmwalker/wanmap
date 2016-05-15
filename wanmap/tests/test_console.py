def test_root_redirects_to_scan_listing(app):
    response = app.get('/', status=302)
    assert response.location.endswith('/scans/')
