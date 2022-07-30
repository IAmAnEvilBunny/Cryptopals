##
# echo-client.py

import socket
from DH import *

# Initiate Bob
bob = DHReceiver(p=int('8977C3217DA1F838B8D24B4A790DE8FC8E35AD5483E463028EF9BBF9AF23A9BD1231EBA9A'
                       'C7E44363D8311D610B09AA224A023268EE8A60AC484FD9381962563', 16),
                 g=int('572AFF4A93EC6214C1036C62E1818FE5E4E1D6DB635C1B12D9572203C47D241A0E543A89B'
                       '0B12BA61062411FCF3D29C6AB8C3CE6DAC7D2C9F7F0EBD3B7878AAF', 16),
                 q=236234353446506858198510045061214171961)

print(f'Secret key is {bob.b}')

factors = [2, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529]
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

        # Create cipher
        bob.key = bob.gen_key()
        print(f'Key is {bob.key}')

        # Send message
        bob.reply = 'Crazy flamboyant for the rap enjoyment'

        # Prepare message and cipher for reply
        bob.encode = bob.gen_encode()

        # Send encrypted message
        ciphertext = bob.encode.cbc_encrypt().easybyte.b  # ciphertext
        macced_ciphertext = bob.add_hmac(ciphertext)
        s.sendall(macced_ciphertext)  # Add HMAC to ciphertext
        print(f'Sent encrypted message')
