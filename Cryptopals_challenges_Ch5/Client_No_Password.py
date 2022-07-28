import socket
from DH import Client
from hashlib import sha256
import hmac

# Initiate client, wishes to login without password
client = Client(b'foo@bar', b'')

# Address
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65435  # Port to listen on (non-privileged ports are > 1023)

# Initiate connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

    # Communicate
    with conn:
        # Send email
        conn.sendall(client.E)

        # Send A (convert first to bytes), make A zero here
        client.A = 0
        conn.sendall(str(client.A).encode())

        # Receive salt
        client.salt = conn.recv(1024)

        # Receive B (int sent as bytes)
        client.B = int(conn.recv(1024).decode())

        # Since we sent A = 0, K = SHA256(0)
        client.K = sha256(str(0).encode()).digest()

        # Send HMAC-SHA256(K, salt)
        conn.sendall(hmac.new(client.K, client.salt, sha256).digest())

        # Receive 'OK' or 'error'
        print(conn.recv(1024).decode())
