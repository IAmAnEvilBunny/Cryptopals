# Class for group operations

import copy
from math import isqrt


def g_el_to_scalar(y, k):
    # Pseudorandom function used in disc_log
    p_rand = pow(2, y, k)
    return p_rand if p_rand != 0 else 1

class AbGroup:
    def __init__(self):
        self.add = self._trivial_add
        self.id = 1
        self.g = 1
        self.q = 1

    @staticmethod
    def _trivial_add(g1, g2):
        # Trivial group operation
        return g1 * g2

    def new_element(self, new_g):
        new = copy.deepcopy(self)
        new.g = new_g
        return new

    def scale(self, k, g=None):
        # Returns self.g ** k
        result = copy.deepcopy(self.id)
        x = copy.deepcopy(self.g) if g is None else g

        while k > 0:
            if k % 2 == 1:
                result = self.add(result, x)
            x = self.add(x, x)
            k = k >> 1

        return result

    @staticmethod
    def prep_key(key_bytes):
        print('This should not be called')

    # TODO: This is ModP centric
    # noinspection PyPep8Naming
    def disc_log(self, start: int, end: int, y, f: callable = g_el_to_scalar):
        """
        Pollard's Method for Catching Kangaroos
        Find x such that g**x mod m = y, with the knowledge that x is between start and end.
        Context: Cyclic groups, ex: multiplication of integers mod m

        Parameters
        ----------
        start : int
            Lowest suspected integer such that g**x = y
        end : int
            Greatest suspected integer such that g**x = y
        y: int
            Group element we are trying to invert
        f: callable
            Pseudorandom function f:G->S taking group elements to scalars

        Returns
        -------
        int, optional
            If x is found such that g**x = y, returns said x
        """
        n = end - start  # Length of interval in which the index lies
        k = isqrt(n) // 2 + 3
        print(f'k is {k}')
        big_n = 2 * k

        def f2(x):
            return f(x, k)

        # Tame kangaroo
        xT = 0
        yT = self.scale(end)

        # Wild kangaroo
        xW = 0
        yW = y

        counter = 0  # Follow progress

        # Tame kangaroo jumps
        for _ in range(big_n):
            jump = f2(yT)  # Function gives us pseudorandom jumpsize
            yT = self.add(yT, self.scale(jump))  # Kangaroo jumps
            xT += jump  # Keep track how far kangaro has jumped (yT *= xT so far)

            # Show progress every so many jumps
            counter += 1
            if counter % 10000 == 0:
                print(f'{counter}/{big_n}')

        # Wild kangaroo catches up to tame kangaroo
        # Distance to cover is between xT and n + xT
        while xW < n + xT:
            jump = f2(yW)  # Function gives us pseudorandom jumpsize
            yW = self.add(yW, self.scale(jump))  # Kangaroo jumps
            xW += jump  # Keep track how far kangaro has jumped (yW *= xW so far)

            # Check whether paths have coincided
            # yW will either land on yT or skip past
            if yW == yT:
                ans = end + xT - xW
                assert self.scale(ans) == y  # Check our answer
                print(ans)
                return ans

            # Show progress every so often
            counter += 1
            if counter % 100000 == 0:
                print(f'{xW}/{xT + n}')

        # If we get this far, the algorithm has not found a solution
        print('Kangaroo has not been caught')


class ModP(AbGroup):
    def __init__(self, p: int, g: int = 1, q=None):
        super().__init__()
        self.p = p
        self.add = self._create_mod_mult(p)
        self.id = 1
        self.g = g
        self.q = q if q is not None else p

    @staticmethod
    def _create_mod_mult(p):
        # Returns multiplication mod p

        def mod_mult(g1, g2):
            # Multiplication mod p
            return (g1 * g2) % p

        return mod_mult

    @staticmethod
    def prep_key(g):
        # Turns a group element into bytes
        int_as_bytes = str(g).encode()  # Transform integer to bytes

        return int_as_bytes

##
test_p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
test_q = 335062023296420808191071248367701059461
test_j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
test_g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
test_y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119

test_group = ModP(test_p, test_g, test_q)
test_group.disc_log(0, 2**20, test_y)

##

