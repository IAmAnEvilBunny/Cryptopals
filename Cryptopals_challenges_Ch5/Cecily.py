# MITM

import socket
from DH import *

# Initiate Cecily
cecily = DHMITM()

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
            cecily.A = int.from_bytes(data_A, 'big')

            # Cecily sends p instead of A to Bob
            to_send = cecily.p.to_bytes(192, 'big')
            conn.sendall(to_send)

            # Cecily receives B from Bob
            data = conn.recv(1024)
            cecily.B = int.from_bytes(data, 'big')

            # Cecily sends p instead of A to Alice
            to_send = cecily.p.to_bytes(192, 'big')
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

            # Decode Alice's and Bob's messages
            A_decoded = AESCode(cecily.A_msg, key=cecily.key, iv=cecily.iv).cbc_solve().decode()
            B_decoded = AESCode(cecily.B_msg, key=cecily.key, iv=cecily.iv).cbc_solve().decode()
            print(f'Alice said {A_decoded}')
            print(f'Bob said {B_decoded}')
