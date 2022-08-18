# Eve is an attacker wishing to crack the receiver's secret key
# in a standard Diffie-Hellman key exchange protocol
# Cryptopals chapter 8

import socket
from DH import DHAttacker, check_hmac
from Group import ModP
from Cryptopals_main import crt, randint, rand_bytes

# Parameters
our_p = int('8977C3217DA1F838B8D24B4A790DE8FC8E35AD5483E463028EF9BBF9AF23A9BD1231EBA9A'
            'C7E44363D8311D610B09AA224A023268EE8A60AC484FD9381962563', 16)
our_g = int('572AFF4A93EC6214C1036C62E1818FE5E4E1D6DB635C1B12D9572203C47D241A0E543A89B'
            '0B12BA61062411FCF3D29C6AB8C3CE6DAC7D2C9F7F0EBD3B7878AAF', 16)
our_q = 236234353446506858198510045061214171961

# Declare our group
our_group = ModP(our_p, our_g, our_q)

# Initiate Eve
eve = DHAttacker(our_group)

# Some small factors of (p-1) / q
factors = [2, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529]
powers = [None] * len(factors)  # Store remainders later on

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

        # Obtain secret key mod factor for each factor
        for j in range(len(factors)):
            factor = factors[j]
            assert (our_p - 1) % factor == 0  # Check factor divides order of group

            # Generate h, an element of order factor
            h = 1
            while h == 1:
                guess = randint(2, our_p - 1)
                h = our_group.scale((our_p - 1) // factor, guess)

            # Eve sends h
            to_send = str(h).encode()  # Convert to bytes
            conn.sendall(to_send)

            # Discard Bob's public key
            _ = conn.recv(1024)

            # Send whatever as iv
            conn.sendall(rand_bytes(16))

            # Receive ciphertext
            eve.rec_msg = conn.recv(1024)
            print(f'Received encrypted message:\n{eve.rec_msg}')

            # Brute force the mac, only 'factor' possibilities
            i = 0
            while powers[j] is None and i < factor:
                eve.s = our_group.scale(i, h)
                potential_key = eve.gen_key()
                if check_hmac(eve.rec_msg, potential_key):
                    # noinspection PyTypeChecker
                    powers[j] = i  # We have cracked secret key mod factor
                i += 1

        # End connection
        conn.sendall(b'STOP')

# Secret key is given by the Chinese remainder theorem
ans = crt(factors, powers)

print(f"Bob's secret key is: {ans}")
