# Challenge 1-2
# Write a function that takes two equal-length buffers and produces their XOR combination.

from EasyByte import EasyByte

def main():
    # Declare byte
    c1_2 = EasyByte('1c0111001f010100061a024b53535009181c', 'hex')

    # XOR it
    xoredc1_2 = c1_2.xor('686974207468652062756c6c277320657965', 'hex')

    # Check we get the expected answer
    assert xoredc1_2.convert('hex') == '746865206b696420646f6e277420706c6179'

    # Print success
    print(f"1.2 passed !\n\n"
          f"1c0111001f010100061a024b53535009181c\nXORed with\n"
          f"686974207468652062756c6c277320657965\nis\n"
          f"746865206b696420646f6e277420706c6179\n\n"
          f"which decoded to text is:\n"
          f"{xoredc1_2.convert('text')}")


if __name__ == "__main__":
    main()
