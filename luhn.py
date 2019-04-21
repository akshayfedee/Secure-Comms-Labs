import json
import binascii
import sys
from Crypto.PublicKey import RSA
import decimal
from operator import mul
from functools import reduce

def random_digit():
    """Return a random digit"""
    return randint(0, 9)


def concat(a, b):
    """Concatenate two strings"""
    return a + b


def new_range(r):
    """Given a number a list or a tuple, return a range.

    If the input is a number, return range(r, r+1).

    If it is a list or a tuple with exactly two elements then return
    the range(lower, upper + 1) where lower is the first element and
    upper is the second.
    """
    if isinstance(r, list) or isinstance(r, tuple) and len(r) == 2:
        lower = r[0]
        upper = r[1]
    else:
        lower = r
        upper = r
    lower = int(lower)
    upper = int(upper)
    return range(lower, upper + 1)


def new_ranges(rs):
    """From a list of valid inputs of new_range function, return the
    chaining of the ranges as a tuple.
    """
    return tuple(chain(*[new_range(r) for r in rs]))


def sum_digits(n):
    """Sum the digits of the number."""
    digits = [int(i) for i in str(n)]
    return sum(digits)


def apply_to_odd_positions(f, xs):
    """Apply the function f to every element in xs that is in a odd
    position leaving the other values unchanged.
    """
    ys = []
    for i, x in enumerate(xs):
        if i % 2 == 1:
            ys.append(f(x))
        else:
            ys.append(x)
    return ys


def double(n):
    """Double of a number"""
    return 2 * n


class Vendor(object):
    def __init__(self, name, ranges, length):
        self.name = name
        self.inns = new_ranges(ranges)
        self.lengths = new_ranges(length)

    def new_card(self):
        length = choice(self.lengths)
        inn = str(choice(self.inns))

        remaining = [str(random_digit())
                     for _ in range(length - len(inn) - 1)]

        remaining = reduce(concat, remaining)

        check_digit = checksum(int(inn + remaining))

        result = int(inn + remaining + str(check_digit))

        assert(verify(result))

        return result


def luhn_digits(n):
    """Given a number, return a list with the digits of Luhn.

    We call Luhn digits of a number the digits that result from
    applying the following operations:

    - Reverse the list of digits
    - Double the value of every second digit
    - If the result of this doubling operation is greater than 9 then
      add the digits of the resulting number.

    These digits are used in both the algorithm that verifies numbers
    and the algorithm that produces new checksums.
    """

    digits = [int(i) for i in str(n)]

    # First, reverse the list of digits.
    digits.reverse()

    # Double the value of every second digit.
    digits = apply_to_odd_positions(double, digits)

    # If the result of this doubling operation is greater than 9 then
    # add the digits of the result.
    digits = apply_to_odd_positions(sum_digits, digits)

    return digits


def verify(n):
    """Check if the credit card number is a valid."""

    # Take the sum of all digits.
    sum_of_digits = sum(luhn_digits(n))

    # The number is valid iff the sum of digits modulo 10 is equal to 0
    return sum_of_digits % 10 == 0


def checksum(n):
    """Checksum digit of the credit card number (with no checksum)."""

    # Compute the sum of the non-check digits.
    s = sum(luhn_digits(n * 10))

    # Multiply by 9.
    result = s * 9

    # The units digit is the check digit
    check_digit = result % 10

    m = int(str(n) + str(check_digit))
    assert(verify(m))

    return check_digit


def vendor(n, vendors_from_inn):
    """Return the issuing vendor of the credit card number."""
    inns = list(map(str, vendors_from_inn.keys()))

    for i in inns:
        if str(n).startswith(i):
            return vendors_from_inn[int(i)]


def generate(v, vendors):
    """Generate a random valid credit card from a issuing vendor."""
    return vendors[v].new_card()


if __name__ == "__main__":
    with open('issuing_networks.json') as f:
        data = json.loads(f.read())

    vendors = {d['name']: Vendor(**d) for d in data['IssuingNetworks']}

    vendors_from_inn = {inn: name for name, v in vendors.items()
                        for inn in v.inns}

    def test():
        v = choice(list(vendors.keys()))
        print("Picked a random vendor: {}".format(v))

        card = generate(v, vendors)
        print("New card for that vendor: {}".format(card))

        vv = vendor(card, vendors_from_inn)
        print("Vendor of new card is: {}".format(vv))

        print("Is card ok?: {}".format(verify(card)))

    def menu():
        print("What do you want to do?")
        print("Options: verify | vendor | checksum | generate | test | exit")
        action = input(">>> ")
        if action in actions:
            print()
            actions[action]()
        print()
        menu()

    def vendor_interactive():
        print("Please enter a credit card number: ")
        n = input(">>> ")
        try:
            n = int(n)
        except ValueError:
            print("Not a number!")
            return

        print(n)
        v = vendor(n, vendors_from_inn)

        if not verify(n):
            print("Invalid credit card number!")
            return

        if v is not None:
            print("The vendor is: {}".format(v))
        else:
            print("I do not know of this inn!")

    def verify_interactive():
        print("Please enter a credit card number: ")
        n = input(">>> ")
        try:
            n = int(n)
        except ValueError:
            print("Not a number!")
            return

        if verify(n):
            print("Valid!")
        else:
            print("This credit card is invalid!")

    def checksum_interactive():
        print("Please enter a credit card number with no checksum: ")
        n = input(">>> ")
        try:
            n = int(n)
        except ValueError:
            print("Not a number!")
            return

        print(checksum(n))

    def generate_interactive():
        vs = list(vendors.keys())

        print("Please select one of our vendors:")
        vendors_list = ["\n    ({}) {}".format(i, v)
                        for i, v in enumerate(vs)]

        print(reduce(concat, vendors_list))
        print()

        try:
            v = vs[int(input('>>> '))]
        except ValueError:
            print("Not a number!")
            return
        except IndexError:
            print("Not in the list!")
            return

        print("Credit card number: {}".format(generate(v, vendors)))

    actions = {
               "menu": menu,
               "verify": verify_interactive,
               "vendor": vendor_interactive,
               "checksum": checksum_interactive,
               "generate": generate_interactive,
               "test": test,
               "exit": exit}
    menu()
