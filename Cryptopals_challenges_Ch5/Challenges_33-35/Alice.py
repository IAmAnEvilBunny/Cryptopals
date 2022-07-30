import socket
from DH import DHSender

# Initiate Alice, argument is message we wish to send
alice = DHSender(b'Hello')

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
