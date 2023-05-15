from test_framework.key import generate_key_pair, generate_bip340_key_pair, ECKey, ECPubKey, jacobi_symbol, SECP256K1_FIELD_SIZE, SECP256K1_ORDER
from test_framework.messages import sha256
from test_framework.script import tagged_hash


###http://localhost:8889/notebooks/1.1-schnorr-signatures.ipynb


### Schorr signature equation S = R + H(x(R)|x(P)|m) * P
### Need nonce (k)
### https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki 
### bip340 defines signature/verifier scheme
### BIP340 constrains private key points k such that the y-value of R is even. This means that from the x co-ordinate, the verifier can unambigiously determine y.
### (Two y-coordinate values for a given x-coordinate)
### Only one will have a y-coordinate which is even. If a randomly generated nonce k does not yield a valid nonce point R, then the signer can negate k to obtain a valid nonce.
### Schorr signature equation S = R + H(x(R)|x(P)|m) * P


###Sign a message with Schnorr

msg = sha256(b"I send you 10 btc")

### Helper function to generate key pair
p, P = generate_key_pair()

# Check that public key point has an even Y-coordinate.
# If not, negate d and P.
if P.get_y() % 2 == 1:
    p.negate()
    P.negate()

# Generate a nonce scalar and associated nonce point
r, R = generate_key_pair()

# Check that nonce point has an even Y-coordinate.
# If not, negate k
if R.get_y() % 2 == 1:
    r.negate()
# Note that there is no need to negate R, since we only use the x value of R below

 ### Generate s = k + hash(R_x|P_x|msg) * d
 ### Tagged_Hash("BIP0340/chalenge", bytes)
 ### ECPubKey.get_bytes() will return the bip340 encoding of a pub key(x coord)

R_bytes = R.get_bytes()
P_bytes = P.get_bytes()
### Dont misspell challenge or sig will not be correct 
h_bytes = tagged_hash("BIP0340/challenge", R_bytes + P_bytes + msg)
h = ECKey().set(h_bytes)

### s = nonce scalar + hash point plus pk scalr
s = r + h * p

#### Generate sig = R_x|s
sig = R_bytes + s.get_bytes()
assert P.verify_schnorr(sig, msg)
print("Success!")


### Generating random nonces is bad 
### Relys on robustness of random generator for each signing round
### If the nonce generator is compromised or even biased, the private key can be derived for a given signature and known nonce.
### BIP340 proposed following nonce generation scheme.  In future lesson we use helper function to generate nonce scaler and point

msg = sha256(b'I will send you 45 bitcoins')
aux = sha256(b'random auxiliary data')

p, P = generate_bip340_key_pair()

###  I dont really undertand this part.  TODO:  Research more
# t is the byte-wise xor of bytes(d) and tagged_hash("BIP0340/aux", aux)
t = (p.secret ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), 'big')).to_bytes(32, 'big')
rand = tagged_hash("BIP0340/nonce", t + P.get_bytes() + msg)

# Generate the nonce value k and get the nonce point R
r, R = generate_key_pair(rand)

# Check that nonce has even y coordinate, If not negate r
if R.get_y() % 2 != 0:
    r.negate()

###Generate signature same as above
R_bytes = R.get_bytes()
P_bytes = P.get_bytes()
### Dont misspell challenge or sig will not be correct 
h_bytes = tagged_hash("BIP0340/challenge", R_bytes + P_bytes + msg)
h = ECKey().set(h_bytes)
### r = nonce scalar, p= private key scaler, h = tagged hash of x coord of nonce + x coord of pubkey + msg
s = r + h * p

# Method: get the x bytes from R and concatenate with the secret bytes from s
sig = R_bytes + s.get_bytes()

# Generate a signature using the ECKey.sign_schnorr(msg) method
# This generates the nonce deterministically, so should return the same signature
sig2 = p.sign_schnorr(msg, aux)

### assert manually cacluated schnorr sig matches the sig of the helper function
assert sig == sig2

print("success")