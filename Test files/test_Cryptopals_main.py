from unittest import TestCase


class TestAESCode(TestCase):
    def test_encrypt(self):
        # 33 characters
        from Cryptopals_main import AESCode
        assert AESCode(b'I like big butts and I cannot lie', key=b'YELLOW SUBMARINE').ecb_encrypt().ecb_solve() == \
               b'I like big butts and I cannot lie'

    def test_encrypt2(self):
        # 32 characters
        from Cryptopals_main import AESCode
        assert AESCode(b'I like big buns and I cannot lie', key=b'YELLOW SUBMARINE').ecb_encrypt().ecb_solve() ==\
               b'I like big buns and I cannot lie'

    def test_cbc_solve(self):
        from Cryptopals_main import AESCode
        assert AESCode(b"I'm sexy and I know it, oh yeah", key=b'YELLOW SUBMARINE',
                       iv=b'I LIKE BIG BUTTS').cbc_encrypt().cbc_solve() ==\
               b"I'm sexy and I know it, oh yeah"
