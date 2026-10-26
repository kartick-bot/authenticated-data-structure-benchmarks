"""Educational KZG commitments using BLS12-381 (py_ecc).

Run: python3 kzg_bls381.py
WARNING: Locally generated SRS is only for experiments, not production.
"""
from secrets import randbelow
from time import perf_counter

from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, add, curve_order, eq, multiply, neg, pairing,
)

R = curve_order


def evaluate(coeffs, x):
    """Evaluate ascending-order polynomial coefficients modulo R."""
    result = 0
    for coefficient in reversed(coeffs):
        result = (result * x + coefficient) % R
    return result


def setup(max_degree):
    """Generate an educational SRS with [tau^i]G1 and [tau]G2."""
    tau = 1 + randbelow(R - 1)
    srs_g1 = [multiply(G1, pow(tau, i, R)) for i in range(max_degree + 1)]
    srs_g2 = [G2, multiply(G2, tau)]
    return srs_g1, srs_g2


def commit(coeffs, srs_g1):
    if len(coeffs) > len(srs_g1):
        raise ValueError('Polynomial degree exceeds SRS capacity')
    result = Z1
    for coefficient, srs_point in zip(coeffs, srs_g1):
        result = add(result, multiply(srs_point, coefficient % R))
    return result


def divide_by_linear(coeffs, z):
    """Return ((f(X)-f(z))/(X-z), f(z)) in ascending order."""
    if not coeffs:
        raise ValueError('Polynomial cannot be empty')
    if len(coeffs) == 1:
        return [0], coeffs[0] % R
    z %= R
    quotient = [0] * (len(coeffs) - 1)
    quotient[-1] = coeffs[-1] % R
    for i in range(len(coeffs) - 2, 0, -1):
        quotient[i - 1] = (coeffs[i] + z * quotient[i]) % R
    remainder = (coeffs[0] + z * quotient[0]) % R
    return quotient, remainder


def open_at(coeffs, z, srs_g1):
    quotient, y = divide_by_linear(coeffs, z)
    return y, commit(quotient, srs_g1)


def verify(commitment, z, y, proof, srs_g2):
    """Check e(C - y*G1, G2) == e(proof, [tau]G2 - z*G2)."""
    lhs_g1 = add(commitment, neg(multiply(G1, y % R)))
    rhs_g2 = add(srs_g2[1], neg(multiply(srs_g2[0], z % R)))
    return pairing(srs_g2[0], lhs_g1) == pairing(rhs_g2, proof)


def main():
    coeffs = [3, 2, 5, 7]
    z = 4
    print('Curve: BLS12-381')
    print('Polynomial: f(X) = 3 + 2X + 5X^2 + 7X^3')
    start = perf_counter()
    srs_g1, srs_g2 = setup(max_degree=len(coeffs) - 1)
    print(f'SRS generation: {(perf_counter() - start)*1000:.3f} ms')

    start = perf_counter()
    C = commit(coeffs, srs_g1)
    print(f'Commitment generation: {(perf_counter() - start)*1000:.3f} ms')

    start = perf_counter()
    y, proof = open_at(coeffs, z, srs_g1)
    print(f'Proof generation: {(perf_counter() - start)*1000:.3f} ms')
    print(f'f({z}) = {y}')
    assert y == evaluate(coeffs, z) == 539

    start = perf_counter()
    valid = verify(C, z, y, proof, srs_g2)
    print(f'Valid proof verification: {(perf_counter() - start)*1000:.3f} ms')
    print(f'Valid opening accepted: {valid}')

    invalid = verify(C, z, y + 1, proof, srs_g2)
    print(f'Incorrect value accepted: {invalid}')
    assert valid and not invalid
    print('All KZG tests passed.')


if __name__ == '__main__':
    main()
