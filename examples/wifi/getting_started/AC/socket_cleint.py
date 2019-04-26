import socket
import sys
#from socket import *
import struct
import binascii
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#print >>sys.stderr, 'connecting to %s port %s' % server_address
# Connect the socket to the port on the server given by the caller
server_address = (sys.argv[1], int(sys.argv[2]))
print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)

try:
    message =struct.pack(">i",13)
    print(binascii.hexlify( message))

    sock.send(message)
    amount_received = 0
    amount_expected = 2
    while amount_received < amount_expected:
        data = sock.recv(3)
        amount_received += len(data)
        print >>sys.stderr, 'received "%s"' % data
    
    message1 = "shiva is here"
    print >>sys.stderr, 'sending "%s"' % message1
    sock.send(message1)
    amount_received = 0
    while amount_received < amount_expected:
        data = sock.recv(16)
        amount_received += len(data)
        print >>sys.stderr, 'received "%s"' % data
finally:
    sock.close()
