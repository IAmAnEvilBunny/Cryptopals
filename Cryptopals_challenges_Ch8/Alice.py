import socket
from DH import *

# Initiate Alice, argument is message we wish to send
alice = DHSender('Hello',
                 p=int('8977C3217DA1F838B8D24B4A790DE8FC8E35AD5483E463028EF9BBF9AF23A9BD1231EBA9A'
                       'C7E44363D8311D610B09AA224A023268EE8A60AC484FD9381962563', 16),
                 g=int('572AFF4A93EC6214C1036C62E1818FE5E4E1D6DB635C1B12D9572203C47D241A0E543A89B'
                       '0B12BA61062411FCF3D29C6AB8C3CE6DAC7D2C9F7F0EBD3B7878AAF', 16),
                 q=236234353446506858198510045061214171961)

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
        alice.encode = alice.gen_encode()  # Holds message and cipher

        # Send iv
        alice.iv = alice.encode.iv
        to_send = alice.iv
        conn.sendall(to_send)
        print(f'iv:\n{to_send}')

        # Receive ciphertext
        alice.rec_msg = conn.recv(1024)
        print(f'Received encrypted message:\n{alice.rec_msg}')

        # Prepare message for decoding
        alice.decode = alice.gen_decode_hmac()

        # Decode
        print(alice.decode.cbc_solve())
        
        # End connection
        conn.sendall(b'STOP')
