# Cecily is the MITM in a standard Diffie-Hellman key exchange protocol

import socket
from Cryptopals_main import AESCode
from DH import DHMITM
from Group import ModP

# Initiate Cecily
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

cecily = DHMITM(our_group)

# Addresses
AHOST = "127.0.0.1"  # The server's hostname or IP address
APORT = 65432  # The port used by the server

BHOST = "127.0.0.1"  # The server's hostname or IP address
BPORT = 65433  # The port used by the server

# Establish connection with A
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((AHOST, APORT))

    # Establish connection with B
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
        t.bind((BHOST, BPORT))
        t.listen()
        conn, addr = t.accept()

        with conn:
            # MITM attack

            # Cecily receives A from Alice
            data_A = s.recv(1024)
            cecily.A = int(data_A.decode())

            # Cecily sends p instead of A to Bob
            to_send = str(our_p).encode()
            conn.sendall(to_send)

            # Cecily receives B from Bob
            data = conn.recv(1024)
            cecily.B = int(data.decode())

            # Cecily sends p instead of A to Alice
            to_send = str(our_p).encode()
            s.sendall(to_send)

            # Receive iv and ciphertext from A
            # Receive iv
            cecily.iv = s.recv(1024)
            print(f'iv:\n{cecily.iv}')

            # Receive ciphertext
            cecily.A_msg = s.recv(1024)
            print(f'Received encrypted message:\n{cecily.A_msg}')

            # Pass iv and ciphertext on to B
            # Send iv
            conn.sendall(cecily.iv)

            # Send ciphertext
            conn.sendall(cecily.A_msg)

            # Receive ciphertext from Bob
            cecily.B_msg = conn.recv(1024)
            print(f'Received encrypted message:\n{cecily.B_msg}')

            # Pass it on to A
            s.sendall(cecily.B_msg)

            # Decode Alice's and Bob's messages TODO: below could go in class
            A_decoded = AESCode(cecily.A_msg, key=cecily.key, iv=cecily.iv).cbc_solve().decode()
            B_decoded = AESCode(cecily.B_msg, key=cecily.key, iv=cecily.iv).cbc_solve().decode()
            print(f'Alice said {A_decoded}')
            print(f'Bob said {B_decoded}')
