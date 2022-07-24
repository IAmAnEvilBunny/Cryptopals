# Challenge 2-2
# Implement CBC mode
from Cryptopals_main import AESCode

def main():
    # Declare ciphertext, key and iv
    c2_10 = AESCode('..\Challenge_2-10.txt', 'b64', key=b'YELLOW SUBMARINE', iv=b'\x00'*16)

    # Print decoded message
    print(c2_10.cbc_solve().decode())


if __name__ == "__main__":
    main()
