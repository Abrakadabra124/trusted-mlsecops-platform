"""Explicit audit mTLS endpoint. No DNS, proxies, URLs, or plaintext fallback."""

import ipaddress
import socket
import ssl
from contextlib import contextmanager

from mlsecops import key_files
from mlsecops import security_event_store as journal
from mlsecops import security_events as events
from mlsecops.contracts import Rejected

SERVICE_NAME = "collector.ml-audit.svc.cluster.local"
FIELDS = ("ca_file", "certificate_file", "key_file")
CLIENT_FIELDS = (*FIELDS, "address", "server_name")
NETWORKS = tuple(
    ipaddress.IPv4Network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


def context(value, *, server):
    for name in FIELDS:
        key_files.read(journal.path(value[name]))
    try:
        result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        result.minimum_version = ssl.TLSVersion.TLSv1_3
        result.verify_mode = ssl.CERT_REQUIRED
        result.load_verify_locations(cafile=value["ca_file"])
        result.load_cert_chain(value["certificate_file"], value["key_file"])
        result.set_alpn_protocols(["http/1.1"])
        return result
    except (OSError, ValueError):
        raise Rejected("security_tls_materials") from None


def server_context(value):
    events.shape(value, FIELDS)
    return context(value, server=True)


class Client:
    def __init__(self, value):
        events.shape(value, CLIENT_FIELDS)
        if type(value["address"]) is not str or value["server_name"] != SERVICE_NAME:
            raise Rejected("security_tls_endpoint")
        try:
            address = ipaddress.IPv4Address(value["address"])
        except ValueError:
            raise Rejected("security_tls_endpoint") from None
        if not any(address in network for network in NETWORKS):
            raise Rejected("security_tls_endpoint")
        self.address, self.server_name = str(address), value["server_name"]
        self.context = context(value, server=False)

    @contextmanager
    def open(self, port, remaining):
        # Numeric AF_INET endpoint: a resolver cannot escape the shared deadline.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(remaining())
            raw.connect((self.address, port))
            raw.settimeout(remaining())
            with self.context.wrap_socket(
                raw, server_hostname=self.server_name, do_handshake_on_connect=False
            ) as connection:
                connection.settimeout(remaining())
                connection.do_handshake()
                remaining()
                yield connection
