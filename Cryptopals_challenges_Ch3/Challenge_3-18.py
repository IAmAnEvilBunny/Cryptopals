# Challenge 3-2
# Implement CTR, the stream cipher mode

from Cryptopals_main import AESCode, empty_bytes

def main():
    # Declare exercise's ciphertext
    c3_2_ciphertext = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

    # Create ciphertext instance with given parameters and ctr decrypt
    c3_2 = AESCode(c3_2_ciphertext, 'b64', key=b'YELLOW SUBMARINE', nonce=empty_bytes(8)).ctr()

    # Print decrypted text
    print(c3_2.easybyte.b)


if __name__ == "__main__":
    main()
