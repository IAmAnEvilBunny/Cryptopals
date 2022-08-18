# Alice is the sender in a standard Diffie-Hellman key exchange protocol

import socket
from DH import DHSender
from Group import ModP

# Initiate Alice, argument is message we wish to send
our_p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
            'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
            '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
            '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
            '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
            'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
            'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
            'fffffffffffff', 16)
our_g = 2
our_group = ModP(our_p, our_g)

alice = DHSender(b'Hello', our_group)

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

        # Alice sends A
        to_send = str(alice.A).encode()
        conn.sendall(to_send)

        # Alice receives B
        data = conn.recv(1024)
        alice.B = int(data.decode())

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

        # Send encrypted message
        to_send = alice.encode.cbc_encrypt().easybyte.b
        conn.sendall(to_send)
        print(f'Sent encrypted message:\n{to_send}')

        # Receive ciphertext
        alice.rec_msg = conn.recv(1024)
        print(f'Received encrypted message:\n{alice.rec_msg}')

        # Prepare message for decoding
        alice.decode = alice.gen_code(alice.rec_msg)

        # Decode
        print(alice.decode.cbc_solve())
