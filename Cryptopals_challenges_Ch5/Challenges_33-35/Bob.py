# Bob is the receiver in a standard Diffie-Hellman key exchange protocol

import socket
from DH import DHReceiver

# Initiate Bob
bob = DHReceiver()

# Address
HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65433  # The port used by the server

# Establish connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Communicate
    # Bob receives A
    data_A = s.recv(1024)
    bob.A = int(data_A.decode())

    # Bob sends B
    to_send = str(bob.B).encode()
    s.sendall(to_send)

    # Bob calculates key
    bob.s = bob.gen_s()
    print(f'Integer for key is {bob.s}')

    # Receive iv
    bob.iv = s.recv(1024)
    print(f'iv:\n{bob.iv}')

    # Receive ciphertext
    bob.rec_msg = s.recv(1024)
    print(f'Received encrypted message:\n{bob.rec_msg}')

    # Create cipher
    bob.key = bob.gen_key()
    print(f'Key is {bob.key}')
    bob.decode = bob.gen_code(bob.rec_msg)

    # Decode and request answer
    print(bob.decode.cbc_solve())
    print('What is your reply ?')
    bob.reply = input().encode()

    # Prepare message and cipher for reply
    bob.encode = bob.gen_code(bob.reply)

    # Send encrypted message
    to_send = bob.encode.cbc_encrypt().easybyte.b
    s.sendall(to_send)
    print(f'Sent encrypted message:\n{to_send}')
