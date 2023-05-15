import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree

### TapLeaf.construct_pk(ECPubKey)
### TapLeaf.construct_pk_hashlock(ECPubKey, 20B-hash-digest)
### TapLeaf.construct_pk_delay(ECPubKey, delay)
### TapLeaf.construct_pk_hashlock_delay(ECPubKey, 20B-hash-digest, delay)


# Generate MuSig key
privkey1, pubkey1 = generate_key_pair()
privkey2, pubkey2 = generate_key_pair()
c_map, pk_musig = generate_musig_key([pubkey1, pubkey2])

if pk_musig.get_y()%2 != 0:
    pk_musig.negate()
    privkey1.negate()
    privkey2.negate()

## pkdelay()
pk_delay_tapscript = TapLeaf().construct_pk_delay(pk_musig, 20)
print("Tapscript descriptor:", pk_delay_tapscript.desc, "\n")

print("Tapscript operations:")
for op in pk_delay_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness elements:")
for element, value in pk_delay_tapscript.sat:
    print("{}, {}".format(element, value.hex()))

digest = hash160(b"data to hash")
pk_hashlock_delay = TapLeaf().construct_pk_hashlock_delay(pk_musig, digest, 20)
print("Tapscript descriptor:", pk_hashlock_delay.desc, "\n")
print("Tapscript operations:")
for op in pk_hashlock_delay.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness elements:")
for element, value in pk_hashlock_delay.sat:
    print("{}, {}".format(element, value.hex()))



'''2.3.5 Programming Exercise: Generate a 2-of-2 csa_hashlock_delay tapscript

Construct a csa_hashlock_delay tapscript with the following locking conditions:

    2-of-2 public keys
    OP_HASH160 hashlock with the preimage sha256(b'secret')
        OP_HASH160 is equivalent to ripemd160(sha256(preimage))
    Delay of 20 blocks
'''



# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()

print("pubkey1: {}".format(pubkey1.get_bytes().hex()))
print("pubkey2: {}\n".format(pubkey2.get_bytes().hex()))

# Method: 32B preimage - sha256(bytes)
# Method: 20B digest - hash160(bytes)
secret = b'secret'
preimage =  sha256(secret)
digest =  hash160(preimage)
delay =  20

# Construct tapscript
csa_hashlock_delay_tapscript =  TapLeaf().construct_csa_hashlock_delay(2, [pubkey1, pubkey2], digest, delay)
print("Descriptor:", csa_hashlock_delay_tapscript.desc, "\n")

print("Tapscript operations:")
for op in csa_hashlock_delay_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness elements:")
for element, value in csa_hashlock_delay_tapscript.sat:
    print("{}, {}".format(element, value.hex()))


'''
    In order to commit a _tapscript_ to a taptweak, we simply compute the 
    `tagged_hash("TapLeaf")` for the tapscript, along with its tapleaf version and then 
    commit the tapleaf to the taptweak.
    *1. **`TapLeaf`** = `sha256(sha256("TapLeaf") + sha256("TapLeaf") + version|size|script)`
    *2. **`TapTweak`** = `sha256(sha256("TapTweak") + sha256("TapTweak") + internal_pubkey + TapLeaf)`
'''

