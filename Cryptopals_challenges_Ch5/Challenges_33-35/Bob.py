# Bob is the receiver in a standard Diffie-Hellman key exchange protocol

import socket
from DH import DHReceiver
from Group import ModP

# Initiate Bob
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

bob = DHReceiver(our_group)

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
