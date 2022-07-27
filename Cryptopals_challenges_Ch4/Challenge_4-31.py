##
import requests
import time

file = 'test_file'

def main():
    # http://127.0.0.1:5000/test is initiated by hmac_web.py
    # http://127.0.0.1:5000/test?file=foo&signature=bar returns whether bar is hmac(file)
    # The comparison is made character by character with early exit and delay between each character
    # The function utilises the time leak to find the signature of a given file

    key = ''  # Initiate key

    # Find characters in key one at a time
    # SHA-1 HMAC is 20 bytes long and so 40 chracters in hex
    for k in range(40):
        times = [0] * 256  # Record times
        max_t = 0  # Placeholder for maximum time
        index = 17  # Placeholder for character yielding max time

        # Search for hex character which causes delay
        for i in range(16):
            # Add character to our key so far and measure response time
            test_byte = hex(i)[2:]
            test_key = key + test_byte
            url = f'http://127.0.0.1:5001/test?file={file}&signature={test_key}'

            # Several trials to average time
            for _ in range(1):
                start = time.time()
                _ = requests.get(url).content
                times[i] += time.time() - start

            # If it took longer than previous max time, record i as index
            if times[i] > max_t:
                max_t = times[i]
                index = i

        # Add the character that took the most time to our key
        key += hex(index)[2:]
        print(f'{k+1}/40')  # See our progress
        print(key)

    # Print result
    print(key)


if __name__ == "__main__":
    main()
