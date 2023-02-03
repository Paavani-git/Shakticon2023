from Crypto.Util.number import *
from gmpy2 import next_prime
from secret import flag

def keygen(nbit):
    while True:
        p = getPrime(512)
        q = int(next_prime(p))
        r = int(next_prime(q))

        if isPrime(p + q + r):
            pubkey = (p * q * r, p + q + r)
            privkey = (p, q, r)
            return pubkey, privkey

def encrypt(msg, pubkey):
    enc = pow(bytes_to_long(msg), 0x10001, pubkey[0] * pubkey[1])
    return enc

nbit = 512
pubkey, _ = keygen(nbit)
print('pubkey =', pubkey)

enc = encrypt(flag, pubkey)
print('enc =', enc)
