# Challenge 4-29
# Break a SHA-1 keyed MAC using length extension

from math import ceil
from SHA_1 import *
from Cryptopals_main import rand_bytes

def main():
    # Generate random key
    key = rand_bytes(8)

    # Declare original (possibly encrypted) message, known to attacker
    og_msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'

    # Sender creates a mac
    og_mac = sha_1(key + og_msg)

    # Number of bytes shaed into og_mac is also known to attacker
    # This is the length of padded (key|msg)
    # Use math.ceil to return the lowest integer greater than the length divided by the blocksize
    # This gives us the number of blocks padded (key|msg) occupies
    l_shaed = ceil((len(key) + len(og_msg)) / 64) * 64  # Blocksize 64

    # Attacker wishes to append an extension to the message without breaking the MAC
    extension = b';admin=true'

    # Extended message attacker wishes to send must include glue padding
    # Result is (og_msg|glue padding|extension)
    # Glue padding is the padding of (key|og_msg)
    # This is a result of picking up SHA where it left off, i.e. after it has already shaed padded (key|msg)
    extended_msg = pad(b'\x00'*len(key) + og_msg)[len(key):] + extension

    # Extend MAC only using original MAC and length of padded (key|msg)
    extended_mac = extend(og_mac, extension, l_shaed)  # attacker created

    # Check this passes authentication, print success or failure
    try:
        # Append mac to extended message in preparation for check_mac
        ext_msg_and_mac = extended_msg + extended_mac
        check_mac(ext_msg_and_mac, key)
        print('Message authenticated !')
    except AssertionError:
        print('Authentication error')


if __name__ == "__main__":
    main()
