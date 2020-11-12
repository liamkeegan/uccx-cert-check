'''
Quick and dirty SSL check for Cisco UCCX installations to make sure your certificates are set properly.
Author: Liam Keegan / github.com/liamkeegan
Version: 1.0
'''

from OpenSSL import SSL
from ssl import PROTOCOL_TLSv1  
import socket
from prettytable import PrettyTable
from datetime import datetime

hosts = ['10.10.20.10']
ports = [443, 7443, 8443, 8444, 8445, 8553, 9443]

x = PrettyTable()
x.field_names = ['Host', 'Port', 'Valid From', 'Valid Until', 'Valid?', 'Issuer', 'Common Name']

for host in hosts:
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        osobj = SSL.Context(PROTOCOL_TLSv1)
        sock.connect((host, int(port)))
        oscon = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(host.encode())
        oscon.set_connect_state()
        oscon.do_handshake()
        cert = oscon.get_peer_certificate()
        sock.close()

        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                        '%Y%m%d%H%M%SZ')
        valid_from = valid_from.strftime('%Y-%m-%d')

        valid_until = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                        '%Y%m%d%H%M%SZ')
        valid_until = valid_until.strftime('%Y-%m-%d')

        is_expired = True if cert.has_expired() else False

        common_name = cert.get_subject().CN

        issuer = cert.get_issuer().CN

        x.add_row([host, port, valid_from, valid_until, is_expired, issuer, common_name])

print(x)
