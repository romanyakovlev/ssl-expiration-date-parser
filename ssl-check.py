from OpenSSL import SSL
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from punnycode import convert_punnycode
from socket import socket
from collections import namedtuple

import sys
import idna
import concurrent.futures

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')


def get_certificate(hostname: str, port=443) -> HostInfo:
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)


def get_common_name(cert: Certificate) -> str:
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def print_basic_info(hostinfo: HostInfo) -> None:
    common_name = convert_punnycode(get_common_name(hostinfo.cert))
    expire_date = hostinfo.cert.not_valid_after
    s = f'{common_name}: {expire_date}'
    print(s)


def read_data(path: str) -> list:
    with open(path, 'r') as f:
        data = f.read().splitlines()
        return data


if __name__ == '__main__':
    hosts = read_data(sys.argv[1])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        for host in e.map(lambda x: get_certificate(x), hosts):
            print_basic_info(host)
