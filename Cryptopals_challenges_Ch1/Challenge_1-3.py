# Challenge 1_3
# Single-byte XOR cipher

from Cryptopals_main import VCode

def main():
    # From the ciphertext declare VCode instance
    c1_3 = VCode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex')

    print(f"Challenge 1.3: XORing\n"
          f"{c1_3.easybyte.convert('hex')}\n"
          f"against all 256 repreating single byte keys,\n"
          f"and filtering for intelligible English yields:\n")

    # XOR our ciphertext against single byte keys
    # The true parameters mean results will be subjected to tests for intelligeble english
    # before corresponding keys are passed to c1_3.keys
    c1_3.single_byte_keys(True, True)

    # Print the text resulting from keys that pass the test
    c1_3.use_keys()


if __name__ == "__main__":
    main()
