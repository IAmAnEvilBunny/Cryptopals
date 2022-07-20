# Challenge 1-1

from EasyByte import EasyByte

def main():
    # Declare byte
    c1_1 = EasyByte('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d',
                    'hex')

    # Check conversion is correct
    assert c1_1.convert('b64') == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    # If correct, print success:
    print(f"1.1 passed !\nhex:\n"
          f"{c1_1.convert('hex')}\nto base64 is:\n"
          f"{c1_1.convert('b64')}")


if __name__ == "__main__":
    main()
