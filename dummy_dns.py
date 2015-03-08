#!/usr/bin/python3

import socketserver
import binascii
import re
import encodings.idna

HOST = '127.0.0.1'
PORT = 9999

class DnsHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        client_add = self.client_address[0]
        domain = data[12:].replace(b"\x00\x00\x01\x00\x01", b"").decode('utf_8') 

        print('recv    (%s): %s' % (client_add, binascii.b2a_hex(data)))  
        print('recv dom(%s): %s' % (client_add, domain))
        
        ## Recursive answer
        ans = data[:2]          # Transaction ID
        ans = ans + b'\x81\x80' # Header(Standerd query response, No Error)
        ans = ans + b'\x00\x01' # QDCOUNT
        ans = ans + b'\x00\x01' # ANCOUNT
        ans = ans + b'\x00\x00' # Authority RRs
        ans = ans + b'\x00\x00' # Additional RRs
        ans = ans + data[12:]   # Queries
        ans = ans + b'\xc0\x0c' # NAME (Message compression is enabled)
        ans = ans + b'\x00\x01' # TYPE
        ans = ans + b'\x00\x01' # CLASS
        ans = ans + b'\x00\x00\x00\x3c' # TTL 120
        ans = ans + b'\x00\x04' # RDLENGTH
        ans = ans + b'\x08\x08\x08\x08' # RDATA(IP address'8.8.8.8')
        
        print('send    (%s): %s' % (client_add, binascii.b2a_hex(ans)))
        socket.sendto(ans, self.client_address)

if __name__ == "__main__":
    server = socketserver.UDPServer((HOST, PORT), DnsHandler)
    try:
        server.serve_forever()
    except:
        print('Dns server stoped...')
