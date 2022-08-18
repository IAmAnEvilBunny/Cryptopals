# Eve is an attacker wishing to crack the receiver's secret key
# in a standard Diffie-Hellman key exchange protocol
# Cryptopals chapter 8

import socket
from DH import *
from Cryptopals_main import crt
from Group import ModP

our_q = 335062023296420808191071248367701059461
our_p = int('DB020645333C52A8D8BD194950CBD48DDF752BAE8F346150C6410DBA6BEFDBC6CF93D7CFC4568FFB017B2'
            '8BEF26242493C606596B7FF8625055F73E888B86117', 16)
our_g = int('BE4ED76592B0FC7A8F2A160840C664BD8A4E0DFF8DED0B2ED0843714C3B7BD12EE50CB56A829A999CA957'
            '14A520BA0C080E7A5866309E4BBCCE1F897EAFB77D', 16)

our_group = ModP(p=our_p, g=our_g, q=our_q)

# Initiate Eve
eve = DHAttacker(our_group)

# Some small factors of (p-1) / q
factors = [2, 12457, 14741, 18061, 31193, 33941, 63803]
fact_prod = 2 * 12457 * 14741 * 18061 * 31193 * 33941 * 63803
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

            # Save Bob's public key
            eve.pub_key = int(conn.recv(1024).decode())

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

print(powers)

# Secret key is given by the Chinese remainder theorem
eve.part_key, eve.part_key_mod = (crt(factors, powers), fact_prod)

print(f"Bob's secret key modulo {eve.part_key_mod} is: {eve.part_key}\n"
      f"Bob's public key is {eve.pub_key}")

ans = eve.kangaroo()

print(f"Bob's secret key is {ans}")
