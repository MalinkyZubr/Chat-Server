import dask
import numba
import cv2
from numba import jit
import time
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
import random
import os

pwd = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(pwd, r'primes.json')


@jit(nopython=True)
def first_test(num):
    if num <= 3 and num > 1:
        return True
    elif num == 1:
        return False
    else:
        return True

@jit(nopython=True)
def second_test(num):
    if not num % 2 or not num % 3:
        return False
    else:
        return True

@jit(nopython=True)
def third_test(num):
    for number in numba.prange(5, int(num ** 0.5), 6):
        if not num % number or not num % (number+2):
            return False
    return True

@jit(nopython=True)
def primality(number):
    first = first_test(number)
    second = second_test(number)
    third = third_test(number)
    if first and second and third:
        return number
    else:
        return False

@jit(nopython=True)
def get_primes():
    prime_list = []
    for num in numba.prange(10000000):
        prime = primality(num)
        if prime:
            prime_list.append(prime)
    return prime_list
        
@jit(nopython=True)
def get_prime_pair(prime_list):
    index1 = random.randint(0, len(prime_list))
    if index1 < 6:
        index2 = index1 + 6
    else:
        index2 = index1 - 3

    return (prime_list[index1], prime_list[index2])


if __name__ == "__main__":
    start_time = time.time()
    x = get_primes()
    with open(filename, "w") as primes:
        primes.write(str(x))

    end_time = time.time()
    print(end_time-start_time)
    start_time = time.time()
    z = get_prime_pair(x)
    end_time = time.time()
    print(end_time-start_time)






