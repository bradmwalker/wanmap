import crypt
import logging

import arrow
import colander
from deform import Form, ValidationFailure, widget
from pyramid.view import view_config

from .schema import LocalUser, User


logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('new_session', '/session', request_method=('GET', 'POST'))
    config.add_route('delete_session', '/session', request_method='DELETE')
    config.add_route('register', '/user')
    config.add_route('show_users', '/users/')
    config.add_route('show_user', '/users/{name}/')
    config.add_route('new_user', '/users/new')


class Login(colander.MappingSchema):
    email = colander.SchemaNode(
        colander.String(),
        validator=colander.Email())
    password = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=8, max=32),
        widget=widget.PasswordWidget(size=20))


@view_config(route_name='new_session', renderer='templates/login.jinja2')
def login_view(request):
    login_schema = Login()
    login_form = Form(login_schema, formid='login', buttons=('submit',))
    if 'submit' in request.POST:
        controls = request.POST.items()
        try:
            appstruct = login_form.validate(controls)
        except ValidationFailure as e:
            return {'login_form': e.render()}
        account = (
            request.dbsession.query(LocalUser).
            filter(LocalUser.email == appstruct['email']).
            one_or_none())
        if not account:
            request.session.flash('No user with that email address recorded.')
            return {'login_form': login_form.render(), 'appstruct': appstruct}
        salt = account.hash[:19]
        hash_ = crypt.crypt(appstruct['password'], salt)
        if hash_ == account.hash:
            request.session['user_name'] = appstruct['email']
        else:
            request.session.flash('Incorrect password.')
        return {'login_form': login_form.render(), 'appstruct': appstruct}
    return {'login_form': login_form.render()}


@view_config(route_name='delete_session', renderer='templates/logout.jinja2')
def logout_view(request):
    request.session.invalidate()
    return {}


class Registration(colander.MappingSchema):
    email = colander.SchemaNode(
        colander.String(),
        validator=colander.Email())
    name = colander.SchemaNode(colander.String())
    password = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=8, max=32),
        widget=widget.PasswordWidget(size=20))


@view_config(route_name='new_user', renderer='templates/register.jinja2')
def register_view(request):
    registration_schema = Registration()
    registration_form = Form(
        registration_schema, formid='register', buttons=('submit',))
    if 'submit' in request.POST:
        controls = request.POST.items()
        try:
            appstruct = registration_form.validate(controls)
        except ValidationFailure as e:
            return {'registration_form': e.render()}
        hash_ = crypt.crypt(appstruct['password'])
        user = LocalUser(
            name=appstruct['name'], email=appstruct['email'], hash=hash_,
            role='user', password_modified=arrow.now().datetime)
        logger.info('Persisting {!r}'.format(user))
        request.dbsession.add(user)
        # TODO: Remove this flush and revisit WebTests... Is this making the
        # transactions work?
        request.dbsession.flush()
        logger.info('Persisted {!r}'.format(user))
        return {
            'registration_form': registration_form.render(),
            'appstruct': appstruct
        }
    return {'registration_form': registration_form.render()}


@view_config(route_name='show_users', renderer='templates/users.jinja2')
def show_users(request):
    users = request.dbsession.query(User).all()
    return {'users': users}
