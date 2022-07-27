import socket
from DH import Server

# Initiate server, arguments are agreed upon email and password
server = Server(b'foo@bar', b'bazquxquux')

# Address
HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65435  # The port used by the server

# Establish connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Communicate
    # Receive email
    email = s.recv(1024)

    # Receive A (int sent as bytes)
    server.A = int(s.recv(1024).decode())

    # Send salt
    s.sendall(server.salt)

    # Send B (must first be converted to bytes)
    s.sendall(str(server.B).encode())

    # Calculate u
    server.u = server.gen_u()

    # Calculate K
    server.K = server.gen_K()

    # Calculate expected HMAC
    server.h = server.gen_h()

    # Receive HMAC-SHA256(K, salt)
    client_h = s.recv(1024)

    # Authenticate
    try:
        assert server.h == client_h
        s.sendall(b'OK')

    except AssertionError:
        s.sendall(b'Error')
