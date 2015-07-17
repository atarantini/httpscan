========
httpscan
========

**Scan networks for HTTP servers, do stuff when you find them.**

Scan networks or hosts for HTTP servers, use **httpscan** definitions
database to fingerprint services or applications and execute custom plugins
over the scan results.

.. contents::
    :local:
    :depth: 2
    :backlinks: none


Usage
-----

Scan your own machine:

.. code-block:: bash

    $ python httpscan.py 127.0.0.1

    2015-07-15 21:18:43,497 - httpscan - DEBUG - Scanning...
    2015-07-15 21:18:43,556 - httpscan - DEBUG - 1 hosts up, 1 total in 0.04s
    2015-07-15 21:18:43,556 - httpscan - DEBUG - 127.0.0.1 Seems to have an HTTP server
    2015-07-15 21:18:43,603 - httpscan - INFO - 127.0.0.1|nginx|{u'website': u'http://nginx.org/', u'vendor': u'nginx', u'class': u'HTTP Server'}

You local network or bigger network segment, with ``--fast`` to improve speed:

.. code-block:: bash

    $ python httpscan.py --fast 192.168.1.1-254

    2015-07-15 21:19:31,282 - httpscan - DEBUG - Scanning...
    2015-07-15 21:19:33,052 - httpscan - DEBUG - 5 hosts up, 254 total in 1.75s
    2015-07-15 21:19:33,052 - httpscan - DEBUG - 192.168.1.1 Seems to have an HTTP server
    2015-07-15 21:19:33,052 - httpscan - DEBUG - 192.168.1.21 Seems to have an HTTP server
    2015-07-15 21:19:33,254 - httpscan - INFO - 192.168.1.1|httpd|None
    2015-07-15 21:19:33,256 - httpscan - INFO - 192.168.1.21|nginx|{u'website': u'http://nginx.org/', u'vendor': u'nginx', u'class': u'HTTP Server'}


Install
-------

You will need to have `Nmap`_ installed. If you are on Debian/Ubuntu, this should
do all the work:

.. code-block:: bash

    $ sudo apt-get install nmap

On OSX you can install with Homebrew or macports:

.. code-block:: bash

    $ brew install nmap

or

.. code-block:: bash

    $ port install nmap

Once you have `Nmap`_ installed, install dependencies from the ``requirements.txt``
file using ``pip``:

.. code-block:: bash

    $ pip install -r requirements.txt

If the project get some stars, I will upload it to the `The Python Package Index`_.


Definitions DB
--------------

In order to identify an HTTP server, **httpscan** use a definition database located in the ``definitions/`` directory.

Definitions are simple JSON files with server name, metadata, signatures/rules for fingerprint and, optionally, a
plugin pipeline that augments the definition of the server.

For example, the ``nginx`` definition located on ``definitions/nginx.json``:

.. code-block:: json

    {
        "name": "nginx",
        "meta": {
            "vendor": "nginx",
            "class": "HTTP Server",
            "website": "http://nginx.org/"
        },
        "rules": {
                "headers": {
                    "server": ["nginx"]
                }
        }
    }

A definition is composed by:

* name (mandatory): Name to describe the server
* meta (optional): Metadata about the server, will be returned in the logs. If you write plugins to gather information, you can extend this field with additional data.
* rules (mandatory): Matching rules to identify the server. Currently the only rule suported is headers/server with a list of regular expressions to identify the server.
* plugins (optional): A list with plugin names that will be executed one after the other forwarding host, definition and response data.

Simple template ready for create a new definition is located on ``definitions/template.json``. Don't forget to create a
pull request or ticket with your definitions in order to share it with the community.

Plugins
-------

When a server is identified by the definition ``rules``, **httpscan** can execute custom plugins located in the ``plugins/`` directory.

Plugins are python files that implement a single function named ``run`` that returns a definition.

The signature for the function is  ``run(host, definition, response)`` where:

* host: Server host/IP
* definition: A dictionary with the definition representation
* response: A ``requests`` response object

Definitions are passed by from one plugin to another and each plugin can augment or extend the server definition.

An example of the ``nginx-version`` plugin (``plugins/nginx-version.py``):

.. code-block:: python

    import re

    REGEX_VERSION = 'nginx/(.*) '

    def run(host, definition, response):
        r = re.compile(REGEX_VERSION)
        match = r.match(response.headers.get('server'))
        groups = match.groups()
        if groups:
            definition[u'meta'][u'version'] = groups[0]

        return definition

This plugin try to fetch the version of the server and extend ``meta`` definition with the ``version`` property that results in

.. code-block:: bash

    2015-07-15 21:19:33,256 - httpscan - INFO - 192.168.1.21|nginx|{'version': '1.2.3', u'website': u'http://nginx.org/', u'vendor': u'nginx', u'class': u'HTTP Server'}


Logging
-------

All important information is stored in ``httpscan.log``:

.. code-block:: bash

    2015-07-13 23:31:53,826 - httpscan - INFO - 192.168.1.218|Avtech|{u'website': u'http://www.avtech.com.tw/', u'vendor': u'AVTECH Corp', u'class': u'IP Camera'}
    2015-07-13 23:31:53,952 - httpscan - INFO - 192.168.1.190|Apache HTTP Server|{u'vendor': u'The Apache Software Foundation', u'class': u'HTTP Server'}
    2015-07-14 20:02:42,892 - httpscan - INFO - 192.168.1.118|Boa|{u'website': u'http://www.boa.org/', u'vendor': u'Boa Webserver', u'class': u'HTTP Server'}
    2015-07-15 21:19:33,254 - httpscan - INFO - 192.168.1.1|httpd|None
    2015-07-15 21:19:33,256 - httpscan - INFO - 192.168.1.21|nginx|{u'website': u'http://nginx.org/', u'vendor': u'nginx', u'class': u'HTTP Server'}


Disclaimer
----------

This software is provided for educational purposes and testing only: use it in
your own network or with permission from the network owner. I'm not responsible
of what actions people decide to take using this software. I'm not not responsible
if someone do something against the law using this software. Please be good and
don't do anything harmful :)


Author
------

Andres Tarantini (atarantini@gmail.com)


License
-------

Released under GNU GPLv3, see COPYING file for more details.

.. _Nmap: http://nmap.org/
.. _`The Python Package Index`: https://pypi.python.org/pypi
