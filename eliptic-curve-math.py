import random
from test_framework.key import generate_key_pair, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1_ORDER

###Following along https://github.com/bitcoinops/taproot-workshop/blob/master/0.2-elliptic-curve-math.ipynb
###can add sub mult and div scalars
###can add and sub point
###can mult and div(Mul point with scalar inverse) scalars and points


### Test that ECKey() method add is the same as adding the scalars

a = random.randrange(1, SECP256K1_ORDER)
b = random.randrange(1, SECP256K1_ORDER)

### normal addition but modulo the result to stay within the SECP256K1_ORDER
a_plus_b = (a + b) % SECP256K1_ORDER
a_minus_b = (a - b) % SECP256K1_ORDER
a_times_b = (a * b) % SECP256K1_ORDER

### use ECKey from test_framework.key to instantiate two ECkey instance with the same random values
a_key = ECKey().set(a)
b_key = ECKey().set(b)

a_key_plus_b_key = a_key + b_key
a_key_minus_b_key = a_key - b_key
a_key_times_b_key = a_key * b_key

### we can add, subtract, multiply and divide ECKey values 
assert a_key_plus_b_key.secret == a_plus_b
assert a_key_minus_b_key.secret == a_minus_b
assert a_key_times_b_key.secret == a_times_b

print("Success!")

###Communitive property of scalar operations
left_plus_right = (a + b) % SECP256K1_ORDER
right_plus_left = b_key + a_key
assert left_plus_right == right_plus_left.secret

###works for multiplication as well
assert (a * b) % SECP256K1_ORDER == (b_key * a_key).secret

###class ECPubkey can be derived from ECKey with the ECKey.get_pubkey method

###can use the generate_key_pair to return a private key public key(ECKey, ECPubKey) pair

a, A = generate_key_pair()
b, B = generate_key_pair()

###can add ECPubKey instances aka points on curve
A_plus_B = A + B
print(A_plus_B)