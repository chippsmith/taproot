from hashlib import sha256

import util
from test_framework.key import ECKey, ECPubKey, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce
from test_framework.messages import sha256
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, sign_musig
from test_framework.script import tagged_hash


### https://eprint.iacr.org/2018/068.pdf

### Need to protect against key cancelation attack
### To counter the key cancellation attack, each participant's pubkey is tweaked by a challenge factor, which is generated by hashing all the participants' pubkeys together.


### generate_musig_key() returns a challenge map and the aggregate public key.
### The challenge map contains ECPubKey_i, challenge_data_i key - value pairs.

# Compute key pairs
privkey1, pubkey1 = generate_key_pair(sha256(b'key0'))
privkey2, pubkey2 = generate_key_pair(sha256(b'key1'))
privkey3, pubkey3 = generate_key_pair(sha256(b'key2'))
pubkeys = [pubkey1, pubkey2, pubkey3]

c_map, pubkey_agg = generate_musig_key(pubkeys)

# Multiply key pairs by challenge factor
privkey1_c = privkey1 * c_map[pubkey1]
privkey2_c = privkey2 * c_map[pubkey2]
privkey3_c = privkey3 * c_map[pubkey3]
pubkey1_c = pubkey1 * c_map[pubkey1]
pubkey2_c = pubkey2 * c_map[pubkey2]
pubkey3_c = pubkey3 * c_map[pubkey3]

# Determine if the private and public keys need to be negated. 
# Hint: The aggregate public key is the one that needs to be valid.
if pubkey_agg.get_y() % 2 != 0:
    privkey1_c.negate() 
    privkey2_c.negate()  
    privkey3_c.negate()  
    pubkey1_c.negate()  
    pubkey2_c.negate()    
    pubkey3_c.negate() 
    pubkey_agg.negate()


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


# Aggregate nonces
# Tip: Add the individual nonce points together. If the aggregated nonce does not have an even Y
# then negate the aggregate nonce and individual nonce scalars.
R_agg =  R1 + R2 + R3

if  R_agg.get_y() % 2 != 0:
    k1.negate()
    k2.negate()
    k3.negate()
    R_agg.negate()

msg = sha256(b'transaction')

# Generate partial signatures
# Method: use sign_musig() with:
#     - individual (tweaked) privkey
#     - individual nonce scalar
#     - aggregate nonce point
#     - aggregate pubkey
#     - msg

s1 = sign_musig(privkey1_c, k1, R_agg, pubkey_agg, msg)
s2 = sign_musig(privkey2_c, k2, R_agg, pubkey_agg, msg)
s3 = sign_musig(privkey3_c, k3, R_agg, pubkey_agg, msg)

sig_agg =  aggregate_musig_signatures([s1, s2, s3], R_agg)

assert pubkey_agg.verify_schnorr(sig_agg, msg)
print("Success! Signature verifies against aggregate pubkey")