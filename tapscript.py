import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree

##BIP 342 https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki

##The pay-to-pubkey tapscript consist of the following script operations:
    ##[pk] [checksig]


##TapLeaf.construct_pk(ECPubKey) contructs a pk tapscript.
##TapLeaf.script returns the script opcodes.
##TapLeaf.sat returns witness elements required to satisfy the tapscript.

# Generate key pair
privkey, pubkey = generate_bip340_key_pair()

# Generate tapscript
pk_tapscript = TapLeaf().construct_pk(pubkey)

print("Tapscript operations:")
for op in pk_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness element:")
for element, value in pk_tapscript.sat:
    print("Witness element type is: {}".format(element))
    print("Signature corresponds to pubkey: {}".format(value.hex()))

###Consturcting checksigadd tapleaf

# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()
privkey3, pubkey3 = generate_bip340_key_pair()

# Generate tapscript.  TapLeaf take m as agrument with list of pubkeys
csa_tapscript = TapLeaf().construct_csa(2, [pubkey1, pubkey2, pubkey3])

print("CSA tapscript operations:")
for op in csa_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

# Satisfying witness element.
print("\nSatisfying witness elements:")
for element, value in csa_tapscript.sat:
    print("Witness element type is: {}".format(element))
    print("Signature corresponds to pubkey: {}".format(value.hex()))

###Alternatively, a k-of-n multisig locking condition can be expressed with multiple k-of-k checksigadd tapscripts. This minimizes leakage of unused public keys and can be more cost-efficient for the spender.
##TapLeaf.generate_threshold_csa(k, [key_0, key_1, ..., key_n])

# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()
privkey3, pubkey3 = generate_bip340_key_pair()

# Generate tapscripts
pubkeys = [pubkey1, pubkey2, pubkey3]
tapscripts = TapLeaf.generate_threshold_csa(2, pubkeys)

print("2-of-3 multisig expressed as 2-of-2 checkigadd tapscripts:")
for ts in tapscripts:
    print(ts.desc)

### TapLeaf.construct_pk(ECPubKey)
### TapLeaf.construct_pk_hashlock(ECPubKey, 20B-hash-digest)
### TapLeaf.construct_pk_delay(ECPubKey, delay)
### TapLeaf.construct_pk_hashlock_delay(ECPubKey, 20B-hash-digest, delay)
