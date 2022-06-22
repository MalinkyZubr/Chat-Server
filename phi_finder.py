import numba
from numba import jit
import time
from math import gcd

@jit(nopython=True)
def is_coprime(x, y):
    return gcd(x, y) == 1

@jit(nopython=True)
def phi(x):
    n = [y for y in range(1, x/2) if is_coprime(x, y)]
    return len(n)

start = time.time()
print(gcd(41687528601119, 485345))
end = time.time()
time = end-start
print(time*1306627313963)