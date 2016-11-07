from wanmap.util import is_ip_network, to_ip_network


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
    assert target == to_ip_network(target)


def test_ipv4_network_to_ip_network():
    target = '10.0.0.0/8'
    assert target == to_ip_network(target)


def test_ipv6_address_to_ip_network():
    target = 'fd12:3456:789a:1::1'
    assert target == to_ip_network(target)


def test_ipv6_network_to_ip_network():
    target = 'fd12:3456:789a:1::/64'
    assert target == to_ip_network(target)


def test_hostname_to_ip_network(fake_dns):
    target = 'example.com'
    ip_network = to_ip_network(target)
    assert target != ip_network
    assert ip_network == '93.184.216.34'
