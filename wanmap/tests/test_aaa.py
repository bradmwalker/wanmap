import crypt
import functools
import logging

import arrow
from psycopg2.errorcodes import UNIQUE_VIOLATION
import pytest
import sqlalchemy.exc


logger = logging.getLogger(__name__)


@pytest.fixture
def persisted_local_user(dbsession):
    from ..schema import LocalUser
    user = LocalUser(
        name='test', email='test@test.com', hash=crypt.crypt('testtest'),
        role='user', password_modified=arrow.now().datetime)
    dbsession.add(user)
    dbsession.flush()
    dbsession.expire(user)
    dbsession.query(LocalUser).get('test@test.com')
    return user


def log_test(test_func):
    @functools.wraps(test_func)
    def _log_test(*args, **kwargs):
        logger.info('Entering {}'.format(test_func.__name__))
        test_func(*args, **kwargs)
        logger.info('Exiting {}'.format(test_func.__name__))
    return _log_test


@log_test
def test_persisted_local_user_has_name(persisted_local_user):
    assert persisted_local_user.name


@log_test
def test_persisted_local_user_has_password(persisted_local_user):
    salt = persisted_local_user.hash[:19]
    assert persisted_local_user.hash == crypt.crypt('testtest', salt=salt)


@log_test
def test_persisted_local_user_has_valid_email(persisted_local_user):
    assert persisted_local_user.email  # is valid


@log_test
def test_persisted_local_user_is_retrievable(dbsession, persisted_local_user):
    from ..schema import User
    account = dbsession.query(User).get(persisted_local_user.name)
    assert account == persisted_local_user


# TODO: py.test -s doesn't seem compatible with -f
@log_test
def test_login_form(app):
    res = app.get('/session', status=200)
    assert res.forms['login']


def _login(app, email, password):
    login_page = app.get('/session', status=200)
    login_form = login_page.forms['login']
    login_form['email'] = email
    login_form['password'] = password
    return login_form.submit('submit')


@log_test
def test_login_submission_succeeds(fresh_app, persisted_local_user):
    res = _login(fresh_app, persisted_local_user.email, 'testtest')
    assert b'flash-messages' not in res.body
    assert 'Set-Cookie' in res.headers


# TODO: Check session values rather than cookies. Cookie is also set for flash
# messages.
@log_test
def test_login_submission_bad_password(fresh_app, persisted_local_user):
    fresh_app.reset()
    res = _login(fresh_app, persisted_local_user.email, 'wrongpassword')
    assert b'Incorrect password.' in res.body
    # assert 'Set-Cookie' not in res.headers


@log_test
def test_login_submission_unknown_email(fresh_app):
    res = _login(fresh_app, 'user@example.com', 'testpassword')
    assert b'No user with that email address recorded.' in res.body
    # assert 'Set-Cookie' not in res.headers


@log_test
def test_fresh_app_unset_cookie(fresh_app):
    res = fresh_app.get('/session', status=200)
    assert 'Set-Cookie' not in res.headers


def _register(app, email, password, name):
    register_page = app.get('/users/new', status=200)
    register_form = register_page.forms['register']
    register_form['email'] = email
    register_form['password'] = password
    register_form['name'] = name
    return register_form.submit('submit')


@log_test
def test_register_invalid_email(app):
    email, password, name = 'user', 'testpassword', 'Test User'
    res = _register(app, email, password, name)
    assert b'Invalid email address' in res.body


@log_test
def test_register_empty_password(app):
    email, password, name = 'user@example.com', '', 'Test User'
    res = _register(app, email, password, name)
    # TODO: key in on element
    assert b'Required' in res.body


@log_test
def test_register_empty_name(app):
    email, password, name = 'user@example.com', 'testpassword', ''
    res = _register(app, email, password, name)
    # TODO: key in on element
    assert b'Required' in res.body


# Need to setup clean dbsession
# Test for valid dbsession ? Cookie?
@log_test
def test_register_and_login(dbsession, fresh_app):
    email, password, name = 'user@example.com', 'testpassword', 'Test User'
    res = _register(fresh_app, email, password, name)
    res = _login(fresh_app, email, password)
    assert 'Set-Cookie' in res.headers
    assert b'flash-messages' not in res.body


@pytest.mark.xfail(
    reason='Why is a unique constraint exception being tested in a WebTest?')
def test_register_existing(dbsession, fresh_app):
    email, password, name = 'user@example.com', 'testpassword', 'Test User'
    _register(fresh_app, email, password, name)
    with pytest.raises(sqlalchemy.exc.IntegrityError) as excinfo:
        _register(fresh_app, email, password, name)
    assert excinfo.value.orig.pgcode == UNIQUE_VIOLATION


def test_crypt_sha512_available():
    assert crypt.METHOD_SHA512


def test_crypt_sha512_strongest():
    assert crypt.methods[0] == crypt.METHOD_SHA512


def test_crypt_sha512_default_salt():
    salt = crypt.crypt('test')
    sha512 = crypt.METHOD_SHA512
    assert salt[1] == sha512.ident
    assert len(salt) == sha512.total_size


ADMIN_USERNAME = 'admin'
def test_admin_user_exists(dbsession):
    from ..schema import User
    assert dbsession.query(User).get(ADMIN_USERNAME)


def test_show_users(app):
    response = app.get('/users/')
    assert ADMIN_USERNAME in response.text
