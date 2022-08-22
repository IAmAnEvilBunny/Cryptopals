# Bob is the receiver in a standard Diffie-Hellman key exchange protocol
# Cryptopals chapter 8

import socket
from DH import DHReceiver
from Group import ModP, CycGroup

# Initiate Bob
our_q = 335062023296420808191071248367701059461
our_p = int('DB020645333C52A8D8BD194950CBD48DDF752BAE8F346150C6410DBA6BEFDBC6CF93D7CFC4568FFB017B2'
            '8BEF26242493C606596B7FF8625055F73E888B86117', 16)
our_g = int('BE4ED76592B0FC7A8F2A160840C664BD8A4E0DFF8DED0B2ED0843714C3B7BD12EE50CB56A829A999CA957'
            '14A520BA0C080E7A5866309E4BBCCE1F897EAFB77D', 16)

our_group = ModP(p=our_p)
our_cyclic_group = CycGroup.from_generator(our_group, our_g, our_q)

bob = DHReceiver(our_cyclic_group)

print(f'Secret key is {bob.b}')

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
        bob.reply = b'Crazy flamboyant for the rap enjoyment'

        # Prepare message and cipher for reply
        bob.encode = bob.gen_code(bob.reply)

        # Send encrypted message
        ciphertext = bob.encode.cbc_encrypt().easybyte.b  # ciphertext
        macced_ciphertext = bob.add_hmac(ciphertext)
        s.sendall(macced_ciphertext)  # Add HMAC to ciphertext
        print(f'Sent encrypted message')
