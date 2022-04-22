import socket
import sys
import struct 


# Scheme for sending : encode in first value the number of elements to be sent (note, this will be hardcoded later on, as the number of elements is known)
# For now, assume number is unknown but not huge

PRECISION = 20 
def to_int(l,precision = PRECISION):
    return [round(v*2**precision) for v in l]


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 3333)
print(f'connecting to {server_address[0]} port {server_address[1]}')
sock.connect(server_address)
vector = [1.1,2.4,5.7,27.9]

try:
    
    # Send data
    vector = to_int(vector)
    vector.insert(0,len(vector))
    print("len vect : ", len(vector))
    messages = struct.pack("<%uI" % len(vector), *vector)
    print("length of message : ",len(messages))
    print(["0x%02x" % b for b in messages])
    
    print("Encoded message : ", messages)
    sock.sendall(messages)
    print("sent message")
    # Look for the response
    amount_received = 0
    amount_expected = len(messages)
    
    while amount_received < amount_expected:
        data = sock.recv(16)
        amount_received += len(data)
        print('received ', data)

finally:
    print('closing socket')
    sock.close()