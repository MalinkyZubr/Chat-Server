import numba
from numba import jit
import time
from math import gcd

@jit(nopython=True)
def is_coprime(x, y):
    return gcd(x, y) == 1

@jit(nopython=True)
def phi(x):
    n = [y for y in range(1, x) if is_coprime(x, y)]
    return len(n)

start = time.time()
phi(96492016611161)
end = time.time()
print(end-start)