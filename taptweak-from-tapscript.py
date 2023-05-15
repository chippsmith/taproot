import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree


'''
    In order to commit a _tapscript_ to a taptweak, we simply compute the 
    `tagged_hash("TapLeaf")` for the tapscript, along with its tapleaf version and then 
    commit the tapleaf to the taptweak.
    *1. **`TapLeaf`** = `sha256(sha256("TapLeaf") + sha256("TapLeaf") + version|size|script)`
    *2. **`TapTweak`** = `sha256(sha256("TapTweak") + sha256("TapTweak") + internal_pubkey + TapLeaf)`
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
    
privkey_internal, pubkey_internal = generate_bip340_key_pair()

# Method: ser_string(Cscript) prepends compact size.
TAPSCRIPT_VER = bytes([0xc0])
tapleaf =  tagged_hash("TapLeaf", TAPSCRIPT_VER +ser_string(csa_hashlock_delay_tapscript.script))
taptweak =  tagged_hash("TapTweak", pubkey_internal.get_bytes() + tapleaf)
print("Your constructed taptweak is: {}.".format(taptweak.hex()))

'''
    A TapTree() object can be instantiated with the internal pubkey key and taptree root root.
    The TapTree.construct() method constructs the triple: segwit_v1_cscript, taptweak, cblock_map.
    Run the code below to generate the taptweak and compare with your taptweak computation.
'''

### makes a tap tree with  the interanl pub key and the tapleaf as arguments
taptree = TapTree(key=pubkey_internal, root=csa_hashlock_delay_tapscript)
### The TapTree.construct() method constructs the triple: segwit_v1_cscript, taptweak, cblock_map.
segwit_v1_script, tap_tweak_constructed, control_map = taptree.construct()

assert taptweak == tap_tweak_constructed
print("Success! Your constructed taptweak is correct.")

### Spending a single tapscript script commitments

taproot_pubkey = pubkey_internal.tweak_add(taptweak)
taproot_pubkey_b = taproot_pubkey.get_bytes()

program = taproot_pubkey_b
print("Witness program is {}\n".format(program.hex()))

version = 0x01
address = program_to_witness(version, program)
print("bech32m address is {}".format(address))

# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))


# Create a spending transaction
# why is version 2??
spending_tx = test.create_spending_transaction(tx.hash, version=2, nSequence=delay)

print("Spending transaction:\n{}".format(spending_tx))

# Generate the Taproot Signature Hash for signing
sighash = TaprootSignatureHash(spending_tx,
                               [tx.vout[0]],
                               SIGHASH_ALL_TAPROOT,
                               input_index=0,
                               scriptpath=  True,
                               script=  csa_hashlock_delay_tapscript.script)

# Sign with both privkeys
signature1 =  privkey1.sign_schnorr(sighash)
signature2 =  privkey2.sign_schnorr(sighash)
print("Signature1: {}".format(signature1.hex()))
print("Signature2: {}".format(signature2.hex()))

# Add witness to transaction
# Tip: Witness stack for script path - [satisfying elements for tapscript] [TapLeaf.script] [controlblock]
# Tip: Controlblock for a tapscript in control_map[TapLeaf.script]
# Why does signature 2 have to be first??
witness_elements =  [preimage, signature2, signature1, csa_hashlock_delay_tapscript.script, control_map[csa_hashlock_delay_tapscript.script]]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))

print("Spending transaction:\n{}\n".format(spending_tx))

# Test mempool acceptance with and without delay
assert not node.test_transaction(spending_tx)
node.generate(delay)
assert node.test_transaction(spending_tx)

print("Success!")

test.shutdown()