#!/usr/bin/env python2
import requests
import logging
from . import ppp
import pyroute2
import ipaddress
import atexit
import subprocess

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

try:
    unicode
except NameError:
    unicode = str

class FingerprintAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to pin a fingerprint for the `requests` library."""
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint
        super(FingerprintAdapter, self).__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, assert_fingerprint=self.fingerprint)

class NXSession(object):
    def __init__(self, options):
        self.options = options
        self.dns_suffixes = []
        self.srv_options = {}
        self.routes = []
        self.interface = None

    def run(self):
        self.host = self.options.server + ':%d' % self.options.port
        self.session = requests.Session()

        if self.options.fingerprint:
            self.session.verify = False
            self.session.mount('https://', FingerprintAdapter(self.options.fingerprint))

        self.session.headers = {
                'User-Agent': 'Dell SonicWALL NetExtender for Linux 8.1.789',
        }

        logging.info("Logging in...")
        self.login(
                self.options.username,
                self.options.password,
                self.options.domain
            )

        logging.info("Starting session...")
        self.start_session()

        logging.info("Dialing up tunnel...")
        self.tunnel()

    def login(self, username, password, domain):
        resp = self.session.post('https://%s/cgi-bin/userLogin' % self.host,
                                 data={
                                     'username': username,
                                     'password': password,
                                     'domain': domain,
                                     'login': 'true',
                                 },
                                 headers={
                                     'X-NE-SESSIONPROMPT': 'true',
                                 },
                                )

        error = resp.headers.get('X-NE-Message', None)
        error = resp.headers.get('X-NE-message', error)
        if error:
            raise IOError('Server returned error: %s' % error)

        atexit.register(self.logout)

    def logout(self):
        # We need to try, but if we went down because we can't talk to the server? - not a big deal.
        try:
            self.session.get('https://%s/cgi-bin/userLogout' % self.host)
        except:
            pass

    def start_session(self):
        """
        Start a VPN session with the server.

        Must be logged in.
        Stores srv_options and routes returned from the server.
        """

        resp = self.session.get('https://%s/cgi-bin/sslvpnclient' % self.host,
                                params={
                                    'launchplatform': 'mac',
                                    'neProto': 3,
                                    'supportipv6': 'no',
                                },
                               )
        error = resp.headers.get('X-NE-Message', None)
        error = resp.headers.get('X-NE-message', error)
        if error:
            raise IOError('Server returned error: %s' % error)

        srv_options = {}
        routes = []
        dns_suffixes = []

        # Very dodgily avoid actually parsing the HTML
        for line in resp.iter_lines():
            line = line.strip().decode('utf-8', errors='replace')
            if line.startswith('<'):
                continue
            if line.startswith('}<'):
                continue

            try:
                key, value = line.split(' = ', 1)
            except ValueError:
                logging.warn("Unexpected line in session start message: '%s'" % line)

            if key == 'Route':
                routes.append(value)
            if key == 'dnsSuffixes':
                dns_suffixes.append(value)
            elif key not in srv_options:
                srv_options[key] = value
            else:
                logging.info('Duplicated srv_options value %s = %s' % (key, value))

            logging.debug("srv_option '%s' = '%s'" % (key, value))

        self.srv_options = srv_options
        self.routes = routes
        self.dns_suffixes = dns_suffixes

    def tunnel(self):
        """
        Begin PPP tunneling.
        """

        tunnel_version = self.srv_options.get('NX_TUNNEL_PROTO_VER', None)

        if tunnel_version is None:
            auth_key = self.session.cookies['swap']
        elif tunnel_version == '2.0':
            auth_key = self.srv_options['SessionId']
        else:
            logging.warn("Unknown tunnel version '%s'" % tunnel_version)
            auth_key = self.srv_options['SessionId']    # a guess

        pppd = ppp.PPPSession(self.options, auth_key, routecallback=self.setup_routes_and_dns, interfacecallback=self.store_interface)
        pppd.run()

    def store_interface(self, interface):
        logging.debug('Interface is %s' % interface)
        self.interface = interface

    def setup_routes_and_dns(self, gateway):
        logging.debug('Remote IP address is %s' % gateway)
        ip = pyroute2.IPRoute()

        for route in set(self.routes):
            net = ipaddress.IPv4Network(unicode(route))
            dst = '%s/%d' % (net.network_address, net.prefixlen)
            ip.route("add", dst=dst, gateway=gateway)

        logging.info("Remote routing configured")

        if self.options.resolved and self.interface:
            dns = [self.srv_options['dns1']]
            if 'dns2' in self.srv_options:
                dns.append(self.srv_options['dns2'])
            subprocess.check_call(['resolvectl', 'dns', self.interface] + dns)
            if self.dns_suffixes:
                subprocess.check_call(['resolvectl', 'domain', self.interface] + self.dns_suffixes)
            logging.info("Configured DNS via resolved")

        logging.info("VPN is up")
