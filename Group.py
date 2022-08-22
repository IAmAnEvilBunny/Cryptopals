# Class for group operations

import copy
from math import isqrt
from random import randint


def g_el_to_scalar(y, k):
    # Pseudorandom function used in disc_log
    p_rand = pow(2, y, k)
    return p_rand if p_rand != 0 else 1


class Group:
    """Base class for groups

    Attributes
    ----------
    id: int = 1
        Identity element

    Parameters
    ----------
    """
    def __init__(self):
        self.add = self._trivial_add
        self.id = 1

    @staticmethod
    def _trivial_add(g1, g2):
        # Trivial group operation
        return g1 * g2

    def scale(self, g, k):
        # Returns self.g ** k
        result = copy.deepcopy(self.id)
        x = g

        while k > 0:
            if k % 2 == 1:
                result = self.add(result, x)
            x = self.add(x, x)
            k = k >> 1

        return result

    def gen_order(self, desired_order: int, grp_order: int):
        # Generate an element of order desired_order
        h = self.id
        while h == self.id:
            guess = randint(2, grp_order)
            h = self.scale(guess, grp_order // desired_order)

        return h

    # TODO: This is ModP centric
    # noinspection PyPep8Naming
    def disc_log(self, start: int, end: int, g, y, f: callable = g_el_to_scalar):
        """
        Pollard's Method for Catching Kangaroos
        Find x such that g**x = y, with the knowledge that x is between start and end.
        Context: Cyclic groups, ex: multiplication of integers mod m

        Parameters
        ----------
        start : int
            Lowest suspected integer such that g**x = y
        end : int
            Greatest suspected integer such that g**x = y
        g
            Group element we took a power of
        y
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
        yT = self.scale(g, end)

        # Wild kangaroo
        xW = 0
        yW = y

        counter = 0  # Follow progress

        # Tame kangaroo jumps
        for _ in range(big_n):
            jump = f2(yT)  # Function gives us pseudorandom jumpsize
            yT = self.add(yT, self.scale(g, jump))  # Kangaroo jumps
            xT += jump  # Keep track how far kangaro has jumped (yT *= xT so far)

            # Show progress every so many jumps
            counter += 1
            if counter % 10000 == 0:
                print(f'{counter}/{big_n}')

        # Wild kangaroo catches up to tame kangaroo
        # Distance to cover is between xT and n + xT
        while xW < n + xT:
            jump = f2(yW)  # Function gives us pseudorandom jumpsize
            yW = self.add(yW, self.scale(g, jump))  # Kangaroo jumps
            xW += jump  # Keep track how far kangaro has jumped (yW *= xW so far)

            # Check whether paths have coincided
            # yW will either land on yT or skip past
            if yW == yT:
                ans = end + xT - xW
                assert self.scale(g, ans) == y  # Check our answer
                print(ans)
                return ans

            # Show progress every so often
            counter += 1
            if counter % 100000 == 0:
                print(f'{xW}/{xT + n}')

        # If we get this far, the algorithm has not found a solution
        print('Kangaroo has not been caught')


class ModP(Group):
    """Multiplicative group of integers mod p

    Attributes
    ----------
    p: int
        Integers are taken mod p
    id: int = 1
        Identity element

    Parameters
    ----------
    p: int
        Integers are taken mod p
    """
    def __init__(self, p: int):
        super().__init__()
        self.p = p
        self.add = self._create_mod_mult(p)
        self.id = 1

    @staticmethod
    def _create_mod_mult(p):
        # Returns multiplication mod p

        def mod_mult(g1, g2):
            # Multiplication mod p
            return (g1 * g2) % p

        return mod_mult


class EGroup(Group):
    """Class for points on an elliptic curve over the finite field F_p.
    These points are endowed with an abelian group structure.
    To be used in elliptic curve Diffie-Hellman key exchange

    Attributes
    ----------
    p: int
        Degree of the field F_p
    a: int
        Coefficient in the equation of the curve
        y^2 = x^3 + ax + b
    b: int
        Constant in the equation of the curve
        y^2 = x^3 + ax + b
    id: str = 'O'
        Identity element

    Parameters
    ----------
    p: int
        Prime number that will be the degree of the field F_p
    a: int
        Coefficient of x in the equation of the curve
        y^2 = x^3 + ax + b
    b: int
        Constant in the equation of the curve
        y^2 = x^3 + ax + b
    """
    def __init__(self, p: int, a: int, b: int):
        super().__init__()
        self.p = p
        self.a = a
        self.b = b
        self.id = 'O'
        self.add = self.e_add

    def check(self, pt) -> bool:
        # Returns True/False depending on whether pt is on the curve
        x, y = pt

        lhs = y**2 % self.p
        rhs = (x**3 + self.a * x + self.b) % self.p

        return lhs == rhs

    def gen_y_squared(self, x):
        y_squared = (x**3 + self.a * x + self.b) % self.p
        print(y_squared)

    def _mod_inv(self, x):
        # Inverts x mod self.p
        return pow(x, self.p - 2, self.p)

    def inverse(self, pt):
        # Inverts group element pt
        x, y = pt

        return x, self.p - y

    def e_add(self, pt, other_pt):
        # Add two group elements pt and other_pt together
        if pt == 'O':
            return other_pt

        if other_pt == 'O':
            return pt

        if self.inverse(pt) == other_pt:
            return 'O'

        x1, y1 = pt
        x2, y2 = other_pt

        if pt == other_pt:
            m = ((3 * x1 ** 2 + self.a) * self._mod_inv(2 * y1))

        else:
            m = (y2 - y1) * self._mod_inv(x2 - x1)

        x3 = (m ** 2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return x3, y3


class CycGroup(Group):
    """Cyclic group

    Attributes
    ----------
    q: int
        Order of the group
    id
        Identity element
    g
        Generator of the group

    Parameters
    ----------
    order: int
        Order of the group
    identity
        Identity element
    g
        Generator of the group
    add_fun: callable
        Function defining how to add two group elements
    """
    def __init__(self, order: int, identity, g, add_fun: callable):
        super().__init__()
        self.add = add_fun
        self.q = order
        self.id = identity
        self.g = g

    @classmethod
    def from_generator(cls, group: Group, element, order: int):
        # Cyclic group is generated from an element of another group
        # This group will have order the order of the element
        return cls(order, group.id, element, group.add)
    
