import socket
import sys
import struct 

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 3333)
print(f'connecting to {server_address[0]} port {server_address[1]}')
sock.connect(server_address)

try:
    
    # Send data
    v = 1000
    message = struct.pack('I',v)
    print("length of message : ",len(message))
    print(["0x%02x" % b for b in message])
    
    print("Encoded message : ", message)
    sock.sendall(message)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    
    while amount_received < amount_expected:
        data = sock.recv(16)
        amount_received += len(data)
        print('received ', data)

finally:
    print('closing socket')
    sock.close()