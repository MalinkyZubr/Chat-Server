import numba
import cv2
from numba import jit
import time
import random
import os

pwd = os.path.dirname(os.path.abspath(__file__))
primes_file = os.path.join(pwd, r'primes.json')


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

def get_primes(ceiling):
    prime_list = []
    for num in numba.prange(ceiling):
        prime = primality(num)
        if prime:
            prime_list.append(prime)
    
    with open(primes_file, "w") as pr:
        pr.write(str(prime_list))
        
    return prime_list
        
def get_prime_pair(primes):
    if not isinstance(primes, list):
        with open(primes, "r") as f:
            print(type(f))
            primes_list = f.readline()
            prime_list = list(map(int,primes_list[1:-1].split(", ")))
    else:
        prime_list = primes

    index1 = random.randint(0, len(prime_list))
    if index1 < 6:
        index2 = index1 + 6
    else:
        index2 = index1 - 3

    return (prime_list[index1], prime_list[index2])







