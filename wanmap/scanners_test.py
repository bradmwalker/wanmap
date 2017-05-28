import logging

from .scanners import Scanner, show_scanners

logger = logging.getLogger(__name__)


def test_show_scanners_without_scanners(view_request):
    response = show_scanners(view_request)
    assert response['scanners'] == []


def test_show_scanners_with_scanners(view_request, fake_wan_scanners):
    response = show_scanners(view_request)
    assert (
        response['scanners'] and
        all(
            isinstance(scanner, Scanner)
            for scanner in response['scanners']))
