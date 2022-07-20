from SHA_1 import sha_1, check_mac

def main():
    # Ciphertext to send
    # (could be encrypted according to any cipher)
    scrambled = b'37ci6q\x00\x98\x23\xaa758g'

    # Secret key
    key = b'clef anglaise'

    # Append mac
    macced_scrambled = scrambled + sha_1(key + scrambled)

    # Authenticate message
    try:
        check_mac(macced_scrambled, key)

        # Print success
        print('Message authenticated !')

    except AssertionError:
        # Print error
        print('Authentication error')


if __name__ == "__main__":
    main()
