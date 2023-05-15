import util
from test_framework.address import program_to_witness
from test_framework.key import ECPubKey, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string
from test_framework.script import tagged_hash, Tapbranch, TapTree, TapLeaf, CScript, TaprootSignatureHash, OP_CHECKSIG, SIGHASH_ALL_TAPROOT

TAPSCRIPT_VER = bytes([0xc0])  # See tapscript chapter for more details.
internal_pubkey = ECPubKey()
internal_pubkey.set(bytes.fromhex('03af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

# Derive pay-to-pubkey scripts
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
scriptA = CScript([pubkeyA.get_bytes(), OP_CHECKSIG])
scriptB = CScript([pubkeyB.get_bytes(), OP_CHECKSIG])
scriptC = CScript([pubkeyC.get_bytes(), OP_CHECKSIG])

# Method: Returns tapbranch hash. Child hashes are lexographically sorted and then concatenated.
# l: tagged hash of left child
# r: tagged hash of right child
def tapbranch_hash(l, r):
    return tagged_hash("TapBranch", b''.join(sorted([l,r])))

# 1) Compute TapLeaves A, B and C.
# Method: ser_string(data) is a function which adds compactsize to input data.
hash_inputA =  TAPSCRIPT_VER + ser_string(scriptA)
hash_inputB =  TAPSCRIPT_VER + ser_string(scriptB)
hash_inputC =  TAPSCRIPT_VER + ser_string(scriptC)
taggedhash_leafA =  tagged_hash("TapLeaf", hash_inputA)
taggedhash_leafB =  tagged_hash("TapLeaf", hash_inputB)
taggedhash_leafC =  tagged_hash("TapLeaf", hash_inputC)

# 2) Compute Internal node TapBranch AB.
# Method: use tapbranch_hash() function
internal_nodeAB = tapbranch_hash(taggedhash_leafA, taggedhash_leafB)

# 3) Compute TapTweak.
rootABC =  tapbranch_hash(internal_nodeAB, taggedhash_leafC)
taptweak =  tagged_hash("TapTweak", internal_pubkey.get_bytes() + rootABC)
print("TapTweak:", taptweak.hex())

# 4) Derive the bech32m address.
taproot_pubkey_b = internal_pubkey.tweak_add(taptweak).get_bytes()
bech32m_address = program_to_witness(1, taproot_pubkey_b)
print('Bech32m address:', bech32m_address)

# Does the same thing as above but with helper functions and checks results are the same
'''The TapTree class allows us to build a taptree structures from TapLeaf objects. It can be instantiated with an internal pubkey key and a taptree root root.

    TapTree.root is the root node of the merkle binary tree.
    TapBranch objects represents internal tapbranches, and have Tapbranch.left and Tapbranch.right members.
    TapTree.construct() returns the triple segwit_v1_script, tweak, control_map.
        segwit_v1_script - segwit v1 output script.
        tweak with the committed taptree.
        control_map stores Cscript - controlblock pairs for spending committed tapscripts.
'''


# Construct tapleaves
tapleafA = TapLeaf().construct_pk(pubkeyA)
tapleafB = TapLeaf().construct_pk(pubkeyB)
tapleafC = TapLeaf().construct_pk(pubkeyC)

# Construct taptree nodes.
tapbranchAB = Tapbranch(tapleafA, tapleafB)
tapbranchABC = Tapbranch(tapbranchAB, tapleafC)

# Construct the taptree.
taptree = TapTree(key=internal_pubkey, root=tapbranchABC)

segwit_v1_script, tweak, control_map = taptree.construct()
print("Your taptweak computed in 2.4.1 is correct:", tweak == taptweak)


### Spending along the script pahth

'''
A Taproot output is spent along the script path with the following witness pattern:

    Witness to spend TapScript_A:
        [Stack element(s) satisfying TapScript_A]
        [TapScript_A]
        [Controlblock c]

Compared to the script spend path of a taproot with a single committed tapscript, the controlblock spending a taproot containing multiple tapscripts will also include a script inclusion proof.

    Controlblock c contains:
        [Tapscript Version]
            0xfe & c[0]
        [Parity bit (oddness of Q's y-coordinate)]
            0x01 & c[0]
        [Internal Public Key]
            c[1:33]
        [Script Inclusion Proof]
            n x 32Bytes
'''


###create address to spend from using helper functions

# Generate key pairs for internal pubkey and pay-to-pubkey tapscripts
privkey_internal, pubkey_internal = generate_bip340_key_pair()

privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()

# Construct pay-to-pubkey tapleaves and taptree
TapLeafA =  TapLeaf().construct_pk(pubkeyA)
TapLeafB =  TapLeaf().construct_pk(pubkeyB)
TapLeafC =  TapLeaf().construct_pk(pubkeyC)
TapLeafD =  TapLeaf().construct_pk(pubkeyD)

# Create a taptree with tapleaves and huffman constructor
# Method: TapTree.huffman_constructor(tuple_list)
taptree =  TapTree(key=pubkey_internal)
taptree.huffman_constructor([(1, TapLeafA), (1, TapLeafB), (1, TapLeafC), (1, TapLeafD)])

# Generate taproot tree with the `construct()` method, then use the taproot bytes to create a bech32m address
taproot_script, tweak, control_map = taptree.construct()
taproot_pubkey = pubkey_internal.tweak_add(tweak) 
program = taproot_pubkey.get_bytes()
address = program_to_witness(1, program)
print("Address: {}".format(address))

### Send Regtest funds to address per usual

# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash, version=2)

print("Spending transaction:\n{}".format(spending_tx))

# Generate the taproot signature hash for signing
sighashA = TaprootSignatureHash(spending_tx,
                               [tx.vout[0]],
                               SIGHASH_ALL_TAPROOT,
                               input_index=0,
                               scriptpath=  True,
                               script=  CScript(TapLeafA.script)
                               )

signatureA =  privkeyA.sign_schnorr(sighashA)

print("Signature for TapLeafA: {}\n".format(signatureA.hex()))

# Add witness to transaction
# Tip: Witness stack for script path - [satisfying elements for tapscript] [TapLeaf.script] [controlblock]
# Tip: Controlblock for a tapscript in control_map[TapLeaf.script]
witness_elements =  signatureA, TapLeafA.script, control_map[TapLeafA.script]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")

test.shutdown()