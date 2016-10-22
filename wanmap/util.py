from ipaddress import ip_network
from itertools import product, starmap
from operator import attrgetter
import socket


__all__ = ['is_ip_network', 'to_ip_network']


def is_ip_network(str_):
    try:
        ip_network(str_)
        return True
    except ValueError:
        return False


def to_ip_network(str_):
    "Currently doesn't attempt resolving AAAA records to IPv6 addresses."
    try:
        ip_network(str_)
        return str_
    except ValueError:
        return socket.gethostbyname(str_)


def intersect_network_sets(nets_a, nets_b):
    """
    Finds all overlapping network blocks between two sets of networks.
    """
    intersections = starmap(intersect_networks, product(nets_a, nets_b))
    non_empty_intersections = set(filter(None, intersections))
    return non_empty_intersections


def intersect_networks(net_a, net_b):
    if net_a.overlaps(net_b):
        return max(net_a, net_b, key=attrgetter('prefixlen'))
