"""
Implementation of the pseudocode for the SHA-1 has function, found at
https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode

SHA-1 is a 20-byte hash function

@author: Lawrence Arscott
"""

from IntAsWord import IntAsWord

# Operations
def bit_not(n, numbits=8):
    # Returns not n, where n is a 'numbits' bits integer
    return (1 << numbits) - 1 - n

def pad(msg: bytes, extending: int = 0):
    # Pre-processing: padding
    # Extending allows us to pad as if 'extending' bytes were prepended to msg
    ml = len(msg) * 8  # Length of message in bits

    if extending:  # Used for extend function: pad taking into account message beforehand
        ml += extending * 8

    msg += b'\x80'  # Append a 1

    # Append 0 ≤ k < 512 bits b'\x00', such that the resulting message length in bits
    # is congruent to −64 ≡ 448 (mod 512)
    msg += ((56 - len(msg)) % 64) * b'\x00'

    # Append ml, the original message length in bits, as a 64-bit big-endian integer.
    # Thus, the total length is a multiple of 512 bits/64 bytes.
    msg += ml.to_bytes(8, 'big')
    assert len(msg) % 64 == 0

    return msg

# Main
def sha_1(msg: bytes,
          h0=0x67452301,
          h1=0xEFCDAB89,
          h2=0x98BADCFE,
          h3=0x10325476,
          h4=0xC3D2E1F0,
          extending=0):

    msg = pad(msg, extending)

    # Process the message in successive 512-bit chunks:
    # Break message into 512-bit chunks
    chunks = [msg[i: i+64] for i in range(0, len(msg), 64)]

    # Break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
    for chunk in chunks:
        words = [int.from_bytes(chunk[i: i+4], 'big') for i in range(0, 64, 4)]

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16, 80):
            new_word = words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
            new_word = IntAsWord(new_word, 32).lrot(1).as_int
            words.append(new_word)
        
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        
        # Main loop:
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((bit_not(b, 32)) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                try:
                    assert 60 <= i <= 79
                except AssertionError:
                    print('i value error in main loop')

                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = IntAsWord(a, 32).lrot(5).as_int + f + e + k + words[i] % 2 ** 32
            e = d
            d = c
            c = IntAsWord(b, 32).lrot(30).as_int
            b = a
            a = temp % 2 ** 32

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) % 2 ** 32
        h1 = (h1 + b) % 2 ** 32
        h2 = (h2 + c) % 2 ** 32
        h3 = (h3 + d) % 2 ** 32
        h4 = (h4 + e) % 2 ** 32

    # Produce the final hash value (big-endian) as a 160-bit number
    # (simply append the 5 32-bit SHA-1 registers):
    hh = ((h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4)

    return hh.to_bytes(20, 'big')

# And
def check_mac(c_text: bytes, key: bytes):
    # Message authentification
    # Checks the received ciphertext is of form:
    # ciphertext | SHA1(key|ciphertext)

    # Separate received bytes into ciphertext and mac
    msg = c_text[:-20]
    mac = c_text[-20:]  # SHA1 -> 20 bytes

    # Perform check
    assert sha_1(key + msg) == mac

def extend(shaed: bytes, extension: bytes, len_og_msg: int):
    # Extend a SHA-ed message with 'extension'
    # Length of original message is required
    # Note that since we are rerunning SHA, the result will be:
    # SHA1(pad(pad(original) + extension))
    
    # Obtain parameters a, b, c, d, e where SHA-1 would have left off
    bin_rep = IntAsWord(int.from_bytes(shaed, 'big'), 160)

    a = int(bin_rep.bin_str(None, 32), 2)
    b = int(bin_rep.bin_str(32, 64), 2)
    c = int(bin_rep.bin_str(64, 96), 2)
    d = int(bin_rep.bin_str(96, 128), 2)
    e = int(bin_rep.bin_str(128, None), 2)
    
    # Restart SHA with those parameters and further bytes to SHA
    return sha_1(extension, a, b, c, d, e, len_og_msg)
