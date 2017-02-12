# wanmap

[![Build Status](https://travis-ci.org/bradmwalker/wanmap.svg?branch=master)](https://travis-ci.org/bradmwalker/wanmap)

WANmap provides a distributed agent framework and central console web application to facilitate large, complex network scanning with [nmap](https://nmap.org/). WANmap differs from [dnmap](https://sourceforge.net/p/dnmap/wiki/Home/) by providing a GUI and (eventually) integrating with routers to optimize scans with routing tables and to facilitate agent administration. WANmap differs from [OpenVAS](https://openvas.org) with (eventual) router integrations and by focusing on network scanning use cases for operations.

## Features

* Scan large networks more quickly by distributing scans to multiple localized agents.
* Determine or validate firewall policy by comparing scan results from two agents.
* Easily demo or develop WANmap with the bundled [mininet](http://mininet.org) virtual WAN testbed.

## License

MIT &copy; [Brad Walker](https://github.com/bradmwalker)
