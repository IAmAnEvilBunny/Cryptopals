from unittest import TestCase


class TestSHA1(TestCase):
    def test_sha_1(self):
        from SHA_1 import sha_1
        assert sha_1(b'Hello World!') ==\
               b'\x2e\xf7\xbd\xe6\x08\xce\x54\x04\xe9\x7d\x5f\x04\x2f\x95\xf8\x9f\x1c\x23\x28\x71'

        assert sha_1(b"Fallait-il que vous m'assassinassiez ?") == \
               b'\xd2\xe6\x18\x86\xef\x6d\xe5\x9d\x58\xe1\x28\xdc\xca\x1d\x20\x18\xcb\x7a\x6a\x38'
