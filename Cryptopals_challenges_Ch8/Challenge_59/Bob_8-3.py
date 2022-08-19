# Bob is the receiver in a standard Diffie-Hellman key exchange protocol
# Cryptopals chapter 8

import socket
from DH import DHReceiver
from Group import EGroup
from Cryptopals_main import parser

# Curve parameters
our_p = 233970423115425145524320034830162017933
our_a = 233970423115425145524320034830162017933 - 95051
our_b = 11279326

# Declare generator and its order
our_g = (182, 85518893674295321206118380980485522083)
our_q = 29246302889428143187362802287225875743

# Declare elliptic curve, pass generator and its order
our_curve = EGroup(our_p, our_a, our_b, our_g, our_q)

# Initiate Bob
bob = DHReceiver(our_curve)

print(f'Secret key is {bob.b}')

# Address
HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server

# Establish connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while True:
        # Communicate
        # Bob receives A
        data_A = s.recv(1024)

        # If no transmission, close connection
        if data_A == b'STOP':
            break

        # A is a group element
        to_parse = data_A.decode()
        print(f'to parse:{to_parse}')
        dic = parser(to_parse)
        bob.A = (int(dic['x']), int(dic['y']))

        # Bob sends group element B
        to_send = f'x={bob.B[0]}&y={bob.B[1]}'.encode()
        s.sendall(to_send)

        # Bob calculates key (a group element)
        bob.s = bob.gen_s()
        print(f'Element for key is {bob.s}')

        # Receive iv
        bob.iv = s.recv(1024)
        print(f'iv:\n{bob.iv}')

        # Create cipher
        bob.key = bob.gen_key()
        print(f'Key is {bob.key}')

        # Send message
        bob.reply = b'Crazy flamboyant for the rap enjoyment'

        # Prepare message and cipher for reply
        bob.encode = bob.gen_code(bob.reply)

        # Send encrypted message
        ciphertext = bob.encode.cbc_encrypt().easybyte.b  # ciphertext
        macced_ciphertext = bob.add_hmac(ciphertext)
        s.sendall(macced_ciphertext)  # Add HMAC to ciphertext
        print(f'Sent encrypted message')
