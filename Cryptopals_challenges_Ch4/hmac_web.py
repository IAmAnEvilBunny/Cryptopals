from flask import Flask, request
from Cryptopals_main import rand_bytes

key = rand_bytes(64)
app = Flask(__name__)

def insecure_compare_sig(dummy: str, target: str, delay=50e-3):
    # Compares strings dummy and target one character at a time with early exit
    # Delay between each comparison is set by delay
    import time  # for delays

    try:
        # Compare characters in order
        for i in range(len(target)):
            # If they match, pause before comparing next set
            if dummy[i] == target[i]:
                time.sleep(delay)

            # If they don't match, early exit
            else:
                return f'Failure{target[i]}{dummy[i]}'

        # Print success if everything matches
        return 'Success'

    # Raise error if we got length of key wrong,
    # but only when we run out of character in either dummy or target
    except IndexError:
        if len(target) > len(dummy):
            return 'Failure: signature too short'

        if len(target) < len(dummy):
            return 'Failure: signature too long'

        else:
            return 'Coding error: index error when dummy and target supposedly have equal length'


@app.route("/")
def home():
    return 'Hello World!'

@app.route("/test")
def test():
    # Searches for file= and signature= in URL
    # Checks signature = hmac(file)
    # File is in text format while signature will be in hex
    from SHA_1 import hmac

    # Obtain values
    file = request.args.get('file')  # text
    signature = request.args.get('signature')  # hex

    # Calculate file's expected hmac
    # Key was initiated on app creation
    expected_hmac = hmac(key, str.encode(file), 'hex')

    # Character-at-a-time comparison with delay and early exit
    return insecure_compare_sig(signature, expected_hmac)


if __name__ == '__main__':
    app.run(port=5001, debug=True)
