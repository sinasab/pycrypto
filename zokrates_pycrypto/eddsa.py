"""
This module implements EdDSA (https://en.wikipedia.org/wiki/EdDSA) signing and verification

1) the signer has two secret values:

    * k = Secret key
    * r = Per-(message,key) nonce

2) the signer provides the verifier with their public key:

    * A = k*B

3) the signer provides a signature consisting of two values:

    * R = Point, image of `r*B`
    * s = Image of `r + (k*t)`

The value `t` denotes the common reference string used by both parties:
    * t = H(R, A, M)
where H() denotes a cryptographic hash function, SHA256 in this implementation.

The nonce `r` is  a random secret, and protects the value `s` from revealing the
signers secret key.

4) the verifier can check the following statement:
    `S*B = R + t*A`

For further information see: https://eprint.iacr.org/2015/677.pdf
based on: https://github.com/HarryR/ethsnarks
"""

import hashlib
import poseidon
from collections import namedtuple
from math import ceil, log2
from os import urandom

from .babyjubjub import JUBJUB_E, JUBJUB_L, JUBJUB_Q, Point
from .field import FQ
from .utils import to_bytes


class PrivateKey(namedtuple("_PrivateKey", ("fe"))):
    """
    Wraps field element
    """

    @classmethod
    # FIXME: ethsnarks creates keys > 32bytes. Create issue.
    def from_rand(cls):
        mod = JUBJUB_L
        # nbytes = ceil(ceil(log2(mod)) / 8) + 1
        nbytes = ceil(ceil(log2(mod)) / 8)
        rand_n = int.from_bytes(urandom(nbytes), "little")
        return cls(FQ(rand_n))

    def sign(self, msg, B=None):
        "Returns the signature (R,S) for a given private key and message."
        B = B or Point.generator()

        A = PublicKey.from_private(self)  # A = kB

        M = msg
        r = hash_to_scalar(self.fe, M)  # r = H(k,M) mod L
        R = B.mult(r)  # R = rB

        # Bind the message to the nonce, public key and message
        hRAM = hash_to_scalar(R, A, M)
        key_field = self.fe.n
        S = (r + (key_field * hRAM)) % JUBJUB_E  # r + (H(R,A,M) * k)

        return (R, S)


class PublicKey(namedtuple("_PublicKey", ("p"))):
    """
    Wraps edwards point
    """

    @classmethod
    def from_private(cls, sk, B=None):
        "Returns public key for a private key. B denotes the group generator"
        B = B or Point.generator()
        if not isinstance(sk, PrivateKey):
            sk = PrivateKey(sk)
        A = B.mult(sk.fe)
        return cls(A)

    def verify(self, sig, msg, B=None):
        B = B or Point.generator()

        R, S = sig
        M = msg
        A = self.p

        lhs = B.mult(S)

        hRAM = hash_to_scalar(R, A, M)
        rhs = R + (A.mult(hRAM))

        return lhs == rhs


def hash_to_scalar(*args):
    """
    Hash the key and message to create `r`, the blinding factor for this signature.
    If the same `r` value is used more than once, the key for the signature is revealed.

    Note that we take the entire 256bit hash digest as input for the scalar multiplication.
    As the group is only of size JUBJUB_E (<256bit) we allow wrapping around the group modulo.
    """
    p = b"".join(to_bytes(_) for _ in args)
    digest = hashlib.sha256(p).digest()
    return int(digest.hex(), 16)  # mod JUBJUB_E here for optimized implementation

def poseidon_hash_to_scalar(input_vec):
    poseidon_simple, _t = poseidon.parameters.case_simple()
    digest = poseidon_simple.run_hash(input_vec)
    print("Output: ", hex(int(digest)))
    return int(digest)

pub_x = 4342719913949491028786768530115087822524712248835451589697801404893164183326
pub_y = 4826523245007015323400664741523384119579596407052839571721035538011798951543
pub_point = Point(FQ(pub_x), FQ(pub_y))
msg = 1234567890123456789012354680980981230981231098

def poseidon_helper(r):
    R = Point.generator().mult(r)
    input_vec = [
        R.x.n,
        R.y.n,
        pub_x,
        pub_y,
        msg
    ]
    print(input_vec)
    return poseidon_hash_to_scalar(input_vec)

def try_find_sig():
    for i in range(1, 1000):
        H = poseidon_helper(i)
        if H % 7 == 0:
            print("Found working r and R")
            print("r: ", i)
            print("R: ", Point.generator().mult(i))

def find_candidates():
    pos = 0
    for s in range(pos, pos+10):
        R = Point.generator().mult(s)
        """
            Print in this format:
            {
                "r": {
                "x": "3319134467327838892242282581065647627392741625699997741597868808889985014067",
                "y": "14491680315471636907755602413083290121075139985873852266585959448729481987981"
                },
                "s": "4"
            },
        """
        print("{")
        print("    \"r\": {")
        print("      \"x\": \"", R.x.n, "\",", sep="")
        print("      \"y\": \"", R.y.n, "\"", sep="")
        print("    },")
        print("    \"s\": \"", s, "\"", sep="")
        print("  },")
        print()
