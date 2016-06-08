from ipaddress import ip_network
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
