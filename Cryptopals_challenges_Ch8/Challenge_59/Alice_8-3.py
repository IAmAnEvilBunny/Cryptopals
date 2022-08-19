# Alice is the sender in a standard Diffie-Hellman key exchange protocol
# Cryptopals chapter 8

import socket
from DH import DHSender
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

# Initiate Alice, argument is message we wish to send
alice = DHSender(b'Hello', our_curve)

# Address
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

# Initiate connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

    # Communicate
    with conn:
        print(f"Connected by {addr}")

        # Alice sends group element A
        to_send = f'x={alice.A[0]}&y={alice.A[1]}'.encode()
        conn.sendall(to_send)

        # Alice receives group element B
        to_parse = conn.recv(1024).decode()
        dic = parser(to_parse)
        alice.B = (int(dic['x']), int(dic['y']))

        # Alice calculates key
        alice.s = alice.gen_s()
        print(f'Integer for key is {alice.s}')

        # Create cipher
        alice.key = alice.gen_key()
        print(f'Key is {alice.key}')
        alice.encode = alice.gen_code(alice.msg_to_send)  # Holds message and cipher

        # Send iv
        alice.iv = alice.encode.iv
        to_send = alice.iv
        conn.sendall(to_send)
        print(f'iv:\n{to_send}')

        # Receive ciphertext
        alice.rec_msg = conn.recv(1024)
        print(f'Received encrypted message:\n{alice.rec_msg}')

        # Prepare message for decoding
        alice.decode = alice.gen_decode_hmac(alice.rec_msg)

        # Decode
        print(alice.decode.cbc_solve())

        # End connection
        conn.sendall(b'STOP')
