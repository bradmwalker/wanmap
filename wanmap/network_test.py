from deform import ValidationFailure
import pytest

from .network import DiscoveryValidator


@pytest.fixture
def discovery_form():
    return DiscoveryValidator.form()


def test_discovery_form_rejects_blank_seed_router_host(discovery_form):
    appstruct = {
        'seed_router_host': '',
        'username': '', 'password': 'wanmap',
    }
    with pytest.raises(ValidationFailure) as exc:
        discovery_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()


def test_discovery_form_rejects_blank_username(discovery_form):
    appstruct = {
        'seed_router_host': '10.1.0.1',
        'username': '', 'password': 'wanmap',
    }
    with pytest.raises(ValidationFailure) as exc:
        discovery_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()


def test_discovery_form_rejects_blank_password(discovery_form):
    appstruct = {
        'seed_router_host': '10.1.0.1',
        'username': 'wanmap', 'password': '',
    }
    with pytest.raises(ValidationFailure) as exc:
        discovery_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()
