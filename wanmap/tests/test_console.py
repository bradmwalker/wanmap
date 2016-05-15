def test_root_redirects_to_scan_listing(app):
    response = app.get('/', status=302)
    assert response.location.endswith('/scans/')


def test_404_page(app):
    response = app.get('/404', status=404)
    assert '404' in response.text
    assert 'Page Not Found' in response.text
