# Challenge 1-7
# AES in ECB mode

from Cryptopals_main import AESCode

def main():
    # Declare AESCode, passing the challenge's ciphertext
    c1_7 = AESCode('../Challenge_1-7.txt', 'b64')

    print(c1_7.easybyte.b)

    # Generate cipher from the key given to us in the challenge
    c1_7.cipher = c1_7.gen_cipher(b'YELLOW SUBMARINE')

    # Print the resulting decryption
    # ecb_solve() returns decryption as a byte string, which we call decode() on
    print(c1_7.ecb_solve().decode())


if __name__ == "__main__":
    main()
