### generating nonce points
# We set the nonces manually here for testing purposes, but usually we'll call generate_schnorr_nonce()
# to generate a random nonce point
# Method: generate_schnorr_nonce() with no argument generates a random nonce

### not sure why not working???
### TODO try with generate_schnorr_nonce

from test_framework.key import ECKey
from test_framework.musig import aggregate_schnorr_nonces
from hashlib import sha256

k1 = ECKey().set(101)
k2 = ECKey().set(222)
k3 = ECKey().set(333)
test_k1 = ECKey().set(k1.secret)
test_k2 = ECKey().set(k2.secret)
test_k3 = ECKey().set(k3.secret)

# Method: use get_pubkey() to get the associated nonce point.
R1 =  k1.get_pubkey()
R2 =  k2.get_pubkey()
R3 =  k3.get_pubkey()

# Round 1: Generate nonce point commitments and exchange them
# Method: use sha256() on the nonce point. sha256() takes a bytes object, so extract the bytes from the nonce point.
R1_digest =  sha256(R1.get_bytes())
R2_digest =  sha256(R2.get_bytes())
R3_digest =  sha256(R3.get_bytes())

# Round 2: Exchange the nonce points. Each participant verifies that the nonce point commitment matches the nonce point.
assert R1_digest.hex() == "38018cfa00483e751b166e7d982a5bb8264fb3309739c2f432e79791a1c9aaf7"
assert R2_digest.hex() == "9eb8fac583a9d83d4753c454e4ab4de833b3496d093a6f2df507a6a39424c745"
assert R3_digest.hex() == "103ea7eeb151bc6bd2c1e54ecaaad303b1c022bb205c5430daac796924a80ed0"

# Aggregate nonces
# Tip: Add the individual nonce points together. If the aggregated nonce does not have an even Y
# then negate the aggregate nonce and individual nonce scalars.
R_agg =  R1 + R2 + R3
if  R_agg.get_y() % 2 != 0:
    k1.negate()
    k2.negate()
    k3.negate()
    R_agg.negate()





print("Individual nonce scalars:\n\t{}, \n\t{}, \n\t{}.\n".format(k1, k2, k3))
print("Aggregate nonce point: {}\n".format(R_agg))

# Test your solution against the aggregate_schnorr_nonces() helper function.
# aggregate_schnorr_nonces() aggregates the nonces and returns whether the individual nonces need to be negated.
test_R_agg, negated = aggregate_schnorr_nonces([R1, R2, R3])
if negated:
    test_k1.negate()
    test_k2.negate()
    test_k3.negate()

assert R_agg == test_R_agg
assert k1 == test_k1
assert k2 == test_k2
assert k3 == test_k3

print("Success!")