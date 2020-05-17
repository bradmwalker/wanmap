from ipaddress import (
    ip_address, ip_interface, ip_network, IPv4Network, IPv6Network,
)

import pytest

from .util import (
    intersect_networks, is_ip_network, to_ip_network,
)


def test_ipv4_address_is_ip_network():
    assert is_ip_network('10.0.0.1')


def test_ipv4_network_is_ip_network():
    assert is_ip_network('10.0.0.0/8')


def test_ipv6_address_is_ip_network():
    assert is_ip_network('fd12:3456:789a:1::1')


def test_ipv6_network_is_ip_network():
    assert is_ip_network('fd12:3456:789a:1::/64')


def test_hostname_is_not_ip_network():
    assert not is_ip_network('example.com')


def test_ipv4_address_to_ip_network():
    target = '10.0.0.1'
    assert IPv4Network(target) == to_ip_network(target)


def test_ipv4_network_to_ip_network():
    target = '10.0.0.0/8'
    assert IPv4Network(target) == to_ip_network(target)


def test_ipv6_address_to_ip_network():
    target = 'fd12:3456:789a:1::1'
    assert IPv6Network(target) == to_ip_network(target)


def test_ipv6_network_to_ip_network():
    target = 'fd12:3456:789a:1::/64'
    assert IPv6Network(target) == to_ip_network(target)


def test_hostname_to_ip_network(fake_dns):
    target = 'example.com'
    ip_network = to_ip_network(target)
    assert target != ip_network
    assert ip_network == IPv4Network('93.184.216.34')


def test_unresolvable_raises_value_error(fake_dns):
    with pytest.raises(ValueError):
        to_ip_network('example.moc')


def test_intersect_networks_nonoverlapping_v4():
    net_a = ip_network('10.0.0.0/8')
    net_b = ip_network('192.168.0.0/16')
    assert intersect_networks(net_a, net_b) is None


def test_intersect_networks_net_a_within_net_b_v4():
    net_a = ip_network('192.168.1.0/24')
    net_b = ip_network('192.168.0.0/16')
    assert intersect_networks(net_a, net_b) == net_a


def test_intersect_networks_equal_networks_v4():
    net_a = ip_network('10.0.0.0/8')
    net_b = ip_network('10.0.0.0/8')
    intersection = intersect_networks(net_a, net_b)
    assert net_a == intersection
    assert net_b == intersection


def test_intersect_networks_net_b_within_net_a_v4():
    net_a = ip_network('10.0.0.0/8')
    net_b = ip_network('10.10.0.0/16')
    assert intersect_networks(net_a, net_b) == net_b


def test_intersect_networks_overlapping_host_net_v4():
    net_a = ip_network('10.0.0.0/8')
    net_b = ip_network('10.10.10.10/32')
    assert intersect_networks(net_a, net_b) == net_b
