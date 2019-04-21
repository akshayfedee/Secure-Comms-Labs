"""Solve the problems of the Zero days RSA challenge.

FEDEE TOYATMA
TU DUBLIN
SECURE COMMS LABS
LECTURER Mark Cummins

Usage:
  python3 solve.py <i> <file>

Parameters:
  <i>        Level number
  <file>     JSON file with the data


"""



import json
import binascii
import sys
from Crypto.PublicKey import RSA
import decimal
from operator import mul
from functools import reduce


# String processing

def string_to_int(s):
    b = bytes(s, 'utf-8')
    return int(binascii.hexlify(b), 16)


def int_to_string(n):
    return binascii.unhexlify(format(n, "x").encode("utf-8")).decode("utf-8")


def format_ans(*params):
    return "ZD{" + ",".join(map(str, params)) + "}"


def encrypt(m, e, n):
    """Encrypt ciphertext using e and n."""
    return pow(m, e, n)


def decrypt(c, d, n):
    """Decript ciphertext using d and n."""
    return pow(c, d, n)


def decryptCRT(c, p, q, dq, dp, qinv):
    """Decript ciphertext using the chinese remainder theorem."""
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    return m


# Math functions

def prod(xs):
    """Product of a list."""
    return reduce(mul, xs)


def gcd(a, b):
    """Greatest common divisor of a and b."""
    while b > 0:
        a, b = b, a % b
    return a


def lcm(a, b):
    """Lowest common multiple of a and b"""
    return a * b // gcd(a, b)


def carmichael_totient(p, q):
    """Return the carmichael totient of p*q."""
    return lcm(p-1, q-1)


def extended_gcd(a, b):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def inverse_modulo(a, n):
    """Return x such that (x * a) % n == 1"""
    g, x, _ = extended_gcd(a, n)
    if g == 1:
        return x % n


def kth_integer_root(n, k):
    """Return the closest integer x such that x ** k == n."""
    decimal.getcontext().prec = len(str(n))
    root = decimal.Decimal(n) ** (decimal.Decimal(1) / decimal.Decimal(k))
    return round(root)


def chinese_remainder_gauss(ns, cs):
    """Return the solution of a chinese remainder system."""
    result = 0
    N = prod(ns)

    for n, c in zip(ns, cs):
        b = N // n
        result += c * b * inverse_modulo(b, n)

    return result % N


# Levels

def level1(n, e, message, **kargs):
    """Use the RSA values to encrypt the message."""
    m = string_to_int(message)
    ciphertext = encrypt(m, e, n)

    return format_ans(ciphertext)


def level2(ciphertext, d, n, **kargs):
    """Use the RSA values to decrypt the ciphertext."""

    c = ciphertext
    m = decrypt(c, d, n)
    M = int_to_string(m)

    return M


def level3(key, **kargs):
    """Return the values n, d and e for the given private key."""

    privateKey = RSA.importKey(key)
    return format_ans(privateKey.n, privateKey.d, privateKey.e)


def level4(key, ciphertext, **kargs):
    """From ciphertext and private key, decrypt the message."""
    publicKey = RSA.importKey(key)
    c = ciphertext
    d = publicKey.d
    n = publicKey.n
    m = decrypt(c, d, n)
    M = int_to_string(m)
    return M


def level5(ciphertext, p, q, dq, dp, qinv, **kargs):
    """From ciphertext and private key values (CRT), decrypt the message."""
    c = ciphertext
    m = decryptCRT(c, p, q, dq, dp, qinv)
    M = int_to_string(m)
    return format_ans(M)


def level6(e, p, q, ciphertext, **kargs):
    """From ciphertext, e, p and q, decrypt the message."""
    c = ciphertext
    n = p * q
    d = inverse_modulo(e, carmichael_totient(p, q))
    m = decrypt(c, d, n)
    M = int_to_string(m)

    return format_ans(M)


def level7(n, e, ciphertext, **kargs):
    """From ciphertext, n and e, decrypt the message."""
    p = 3133337  # Discovered using factorDB
    q = n // p
    return level6(e, p, q, ciphertext)


def level8(ciphertext, e, n, **kargs):
    """From ciphertext, n and e, decrypt the message."""

    # We know that c = m^e mod n
    # Maybe m^e is less than n. If that is the case:
    # c = m^e
    # Then we just need to compute the eth integer root:
    # m = c^(1/e)
    # Let's try it!
    c = ciphertext
    m = kth_integer_root(c, e)
    M = int_to_string(m)
    return format_ans(M)


def level9(e, n1, c1, n2, c2, n3, c3, **kargs):
    """From two ciphertexts and two public keys with the same e decrypt
       the message."""

    # First, we check that n1, n2 y n3 are indeed coprime
    # If not, this method won't work

    assert(gcd(n1, n2) == 1 and gcd(n1, n3) == 1 and gcd(n2, n3) == 1)

    # Let x be m ^ e.
    # Because we know how to find big integer kth roots,
    # we can easily compute m from x. Let's find x.

    # Let N be n1 * n2 * n3
    # Given that n1, n2, n3 are coprime and that:
    # x % n1 = c1
    # x % n2 = c2
    # x % n3 = c3
    #
    # We know (thanks to the chinese remainder theorem) that there is
    # a unique solution for these equations that 0 <= x < N!
    # In fact, there is an algorithm to found that solution. Let's use
    # it:

    x = chinese_remainder_gauss([n1, n2, n3], [c1, c2, c3])

    # Remember that x = m ^ e. Then:

    m = kth_integer_root(x, e)
    M = int_to_string(m)

    return format_ans(M)


def bezout_numbers(a, b):
    x = inverse_modulo(a, b)
    y = (gcd(a, b) - a * x) // b
    return x, y


def level10(n1, n2, e1, e2, c1, c2, **kargs):
    assert(n1 == n2)
    n = n1
    assert(gcd(e1, e2) == 1)
    assert(gcd(c2, n) == 1)

    # Remember that Bezout’s Theorem states that if there are two
    # non zero integers a and b, then there are integers x and y
    # such that x*a + y*b = gcd(a, b)

    # We know that:
    # c1 = m^e1 % n
    # c2 = m^e2 % n
    # gcd(e1, e2) == 1       (*)

    # We can apply the theorem to (*). Now we know that there are
    # x and y such that:
    # x*e1 + y*e2 = gcd(e1, e2) = 1
    # x*e1 + y*e2 = 1

    # Therefore
    # m = m^1
    #   = m^(x*e1 + y*e2)
    #   = m^(x*e1) * m^(y*e2)
    #   = (m^e1)^x * (m^e2)^y
    #   = (c1^x * c2^y) % n

    # So we only need to find x and y to crack the cipher!
    # There is an algorithm for doing just that:

    x, y = bezout_numbers(e1, e2)

    # Great! Now lets compute (c1^x * c2^y) % n to find m.
    # But wait! there is a problem:

    assert(y < 0)

    # The algorithm we used always returns a negative number. So we
    # need to first take the inverse of c2 and the compute the power:

    c2inv = inverse_modulo(c2, n)

    # Done!

    m = pow(c2inv, -y, n) * pow(c1, x, n) % n

    M = int_to_string(m)

    return format_ans(M)


def level11(n, e, c, dp, **kargs):

    # First we need to prove the following result:
    #
    # Theorem 1
    # ---------
    # Let a, b be integers and p some prime number.
    # If b = 1 mod (p-1) then a^b = a mod p
    #
    # Proof
    # -----
    # If p divides a then the result is inmediate.
    # Assume p does not divide a. Then, by Fermat's little theorem:
    # a^(p-1) = 1 (mod p)     [1]
    #
    # Given that b = 1 mod (p-1), there exists a integer k such that
    # b - 1 = k * (p-1)       [2]
    #
    # Then
    #
    # 1 = 1^k            (mod p)
    #   = (a^(p-1))^k    (mod p)    applying [1]
    #   = (a^(b-1))      (mod p)    applying [2]
    #
    # But then:
    #
    # a = a^b (mod p)
    #
    # q.e.d.

    # Now, observe that e and dp are inverses modulo p-1. Then:
    # e*dp = 1 (mod p-1)
    #
    # By virtue of the Theorem 1 for any integer a:
    # a^(e*dp) = a mod p
    #
    # But then p is a factor of a^(e*dp) - a. We can use this
    # to factorize n by computing gcd(n, (a^(e*dp) - a) % n) where a is
    # some random number.

    a = 3  # Random enough
    p = gcd(n, pow(a, (e * dp), n) - a % n)
    q = n // p

    assert(p * q == n and p != n and q != n)

    d = inverse_modulo(e, carmichael_totient(p, q))
    m = decrypt(c, d, n)
    M = int_to_string(m)
    return format_ans(M)


levels = [level1, level2, level3, level4, level5, level6, level7,
          level8, level9, level10, level11]


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__)
        exit(2)

    n = int(sys.argv[1])
    filename = sys.argv[2]

    if n not in range(1, len(levels) + 1):
        error_msg = "The level number should be a number between 1 and {}"
        print(error_msg.format(len(levels)))
        print()
        print(__doc__)
        exit(2)

    try:
        with open(filename) as f:
            data = json.loads(f.read())
    except Exception as err:
        print(err)
        exit(2)

    data_of_level = data[str(n)]

    ans = levels[int(n)-1](**data_of_level)

    print(ans)
