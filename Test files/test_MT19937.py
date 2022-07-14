from unittest import TestCase
from MT19937 import IntAsWord, MT19937

class TestByteAsInt(TestCase):
    def test_trailing_zeroes(self):
        test_case = IntAsWord(8, 4)
        n_trailing = test_case.bin_trailing_zeroes()
        assert n_trailing == 3

class TestMT19937(TestCase):
    def test_untemper(self):
        # Testing the untemper function

        # Generate MT19937 instance
        mt = MT19937()

        # Check several cases
        for i in range(10):
            import copy
            from random import randint
            og = randint(0, 2*mt.w - 1)  # start with a random integer
            y = copy.deepcopy(og)  # make a copy to temper and untemper

            # do tempering step
            y = mt.temper(y)

            # undo tempering step
            y = mt.untemper(y)

            # check we're back where we started
            assert y == og
