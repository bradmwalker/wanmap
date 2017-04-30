from . import schema


def test_session_factory_is_singleton(appsettings, session_factory):
    new_session_factory = schema.get_session_factory(appsettings)
    assert new_session_factory is session_factory
