import numba
from numba import jit

@jit(nopython=True)
def gcd(self, p, q):
    while q != 0:
        p, q = q, p % q
    return p

@jit(nopython=True)
def is_coprime(self, x, y):
    return self.gcd(x, y) == 1

@jit(nopython=True)
def phi(self, x):
    if x == 1:
        return 1
    else:
        n = [y for y in range(1, x) if self.is_coprime(x, y)]
        return len(n)