from hashlib import sha256
from test_framework.key import ECKey, ECPubKey, generate_key_pair, generate_bip340_key_pair
from test_framework.musig import generate_musig_key, sign_musig, aggregate_musig_signatures


### First I want to create a Musig Spend
###privkey1, pubkey1 = generate_key_pair(sha256(b'key0'))
p1, P1 = generate_bip340_key_pair()
p2, P2 = generate_bip340_key_pair()
p3, P3 = generate_bip340_key_pair()

pubkeys = [P1, P2, P3]

### generate_musig_key() returns a challenge map and the aggregate public key.
### The challenge map contains ECPubKey_i, challenge_data_i key - value pairs.

c_map, pubkey_agg = generate_musig_key(pubkeys)

# Multiply key pairs by challenge factor
p1_c = p1 * c_map[P1]
p2_c = p2 * c_map[P2]
p3_c = p3 * c_map[P3]

P1_c = p1 * c_map[P1]
P2_c = p2 * c_map[P2]
P3_c = p3 * c_map[P3]

# IF aggregate pubkey y value is negative negate all other keys

if pubkey_agg.get_y() %2 != 0:
    p1_c.negate()
    p2_c.negate()
    p3_c.negate()
    P1_c.negate()
    P2_c.negate()
    P3_c.negate()
    pubkey_agg.negate()

### generate nonces

r1, R1 = generate_key_pair()
r2, R2 = generate_key_pair()
r3, R3 = generate_key_pair()

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
    r1.negate()
    r2.negate()
    r3.negate()
    R_agg.negate()

msg = sha256(b'I will send you money').digest()

s1 = sign_musig(p1_c, r1, R_agg, pubkey_agg, msg)
s2 = sign_musig(p2_c, r2, R_agg, pubkey_agg, msg)
s3 = sign_musig(p3_c, r3, R_agg, pubkey_agg, msg)

sig_agg = aggregate_musig_signatures([s1, s2, s3], R_agg)

assert pubkey_agg.verify_schnorr(sig_agg, msg)

print("Success! Signature verifies against aggregate pubkey")