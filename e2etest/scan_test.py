import time

import pytest
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select

PING_SWEEP = '-sn -PE -n'


@pytest.mark.nondestructive
def test_fake_wan_scanners_online(base_url, selenium):
    selenium.implicitly_wait(3)
    selenium.get(base_url)

    scanners_link = selenium.find_element_by_id('show-scanners')
    scanners_link.click()

    fake_wan_scanner_names = 'dmzscanner', 'external', 'scanner1', 'scanner2'
    for scanner_name in fake_wan_scanner_names:
        query = '//tr[td/a/text()="{}"]'.format(scanner_name)
        scanner_row = selenium.find_element_by_xpath(query)
        assert scanner_row


@pytest.mark.selenium
def test_splitting_scan_live(base_url, selenium):
    selenium.implicitly_wait(3)
    selenium.get(base_url)

    new_scan_link = selenium.find_element_by_id('new-splitting-scan')
    new_scan_link.click()

    # TODO: Rename field buttons
    add_scan_target = selenium.find_element_by_id('deformField2-seqAdd')
    add_scan_target.click()
    nmap_options = selenium.find_element_by_name('nmap_options')
    nmap_options.send_keys(PING_SWEEP)
    scan_targets = selenium.find_elements_by_name('scan_target')
    scan_targets[0].send_keys('10.1.0.1')
    scan_targets[1].send_keys('10.2.0.1')
    scan_targets[1].send_keys(Keys.ENTER)

    time.sleep(5)
    scan_results = selenium.find_element_by_id('scanner1-results').text
    assert '<address addr="10.1.0.1" addrtype="ipv4"/>' in scan_results
    scan_results = selenium.find_element_by_id('scanner2-results').text
    assert '<address addr="10.2.0.1" addrtype="ipv4"/>' in scan_results


@pytest.mark.selenium
def test_delta_scan_live(base_url, selenium):
    """Quickly test a delta scan."""
    selenium.get(base_url)

    new_scan_link = selenium.find_element_by_id('new-delta-scan')
    new_scan_link.click()

    # TODO: Rename field buttons
    nmap_options = selenium.find_element_by_name('nmap_options')
    nmap_options.send_keys(PING_SWEEP)
    scanner_a = Select(selenium.find_element_by_name('scanner_a'))
    scanner_a.select_by_value('external')
    scanner_b = Select(selenium.find_element_by_name('scanner_b'))
    scanner_b.select_by_value('dmzscanner')
    scan_target = selenium.find_element_by_name('scan_target')
    scan_target.send_keys('203.0.113.1')
    scan_target.submit()

    time.sleep(5)
    scan_results = selenium.find_element_by_id('external-results').text
    assert '<address addr="203.0.113.1" addrtype="ipv4"/>' not in scan_results
    scan_results = selenium.find_element_by_id('dmzscanner-results').text
    assert '<address addr="203.0.113.1" addrtype="ipv4"/>' in scan_results


@pytest.mark.parametrize('trial', range(5))     # Retry test of nondeterminism
@pytest.mark.selenium
def test_fastest_scan_successfully_completes(base_url, selenium, trial):
    """Tests the scan status event timing. When a subscan duration is extremely
    short (~100ms), the mark started and subscan completion transactions race,
    sometimes causing a subscan that never completes.
    """

    selenium.implicitly_wait(3)
    selenium.get(base_url)

    new_scan_link = selenium.find_element_by_id('new-splitting-scan')
    new_scan_link.click()

    # TODO: Rename field buttons
    nmap_options = selenium.find_element_by_name('nmap_options')
    nmap_options.send_keys(PING_SWEEP)
    scan_targets = selenium.find_elements_by_name('scan_target')
    scan_targets[0].send_keys('10.1.0.1')
    scan_targets[0].send_keys(Keys.ENTER)

    time.sleep(5)
    scan_status = selenium.find_element_by_id('scan-status').text
    assert scan_status == 'Completed'
