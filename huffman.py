import util
from test_framework.key import ECKey, ECPubKey, generate_key_pair, generate_bip340_key_pair
from test_framework.script import Tapbranch, TapLeaf, TapTree

### http://localhost:8889/notebooks/2.5-huffman.ipynb
'''Example 2.5.1: Construct a TapTree with the Huffman algorithm
We manually construct the TapTree from a set of 5 pay-to-pubkey TapLeaves with assigned frequencies as shown in the image above.
'''

internal_pubkey = ECPubKey()
internal_pubkey.set(bytes.fromhex('af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

# Derive pay-to-pubkey tapleaves
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()
privkeyE, pubkeyE = generate_bip340_key_pair()

tapleafA = TapLeaf().construct_pk(pubkeyA)
tapleafB = TapLeaf().construct_pk(pubkeyB)
tapleafC = TapLeaf().construct_pk(pubkeyC)
tapleafD = TapLeaf().construct_pk(pubkeyD)
tapleafE = TapLeaf().construct_pk(pubkeyE)

# Sorted queue: (5, A), (4, B), (3, C), (2, D), (1, E)
# Tapbranch DE = parent(D,E)
# Assigned frequency of DE = 2 + 1 = 3
tapbranchDE = Tapbranch(tapleafD, tapleafE)

# Sorted queue: (5, A), (4, B), (3, C), (3, DE), 
# Tapbranch CDE = parent(C, DE)
# Assigned frequency of CDE = 3 + 3 = 6
tapbranchCDE = Tapbranch(tapleafC, tapbranchDE)

# Sorted queue: (6, CDE), (5, A), (4, B)
# Tapbranch AB = parent(A,B)
# Assigned frequency of AB = 5 + 4 = 9
tapbranchAB = Tapbranch(tapleafA, tapleafB)

# Sorted queue: (9, AB), (6, CDE)
# Tapbranch ABCDE = parent(AB, CDE)
tapbranchABCDE = Tapbranch(tapbranchAB, tapbranchCDE)

# Tree construction
taptree = TapTree(key=internal_pubkey, root=tapbranchABCDE)

segwit_v1_script, tweak, control_map = taptree.construct()
print("Taptree descriptor: {}\n".format(taptree.desc))


###Consruct same tree with huffman method

taptree2 = TapTree()
taptree2.key = internal_pubkey
taptree2.huffman_constructor([(5, tapleafA), (4, tapleafB), (3, tapleafC), (2, tapleafD), (1, tapleafE)])
print("Taptree descriptor: {}\n".format(taptree2.desc))

segwit_v1_script2, tweak2, control_map2 = taptree2.construct()
print("TapTrees are identical: {}".format(tweak == tweak2))

### Programming excercize 2.5.3


internal_pubkey = ECPubKey()
internal_pubkey.set(bytes.fromhex('af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

# Derive pay-to-pubkey TapLeaves
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()
privkeyE, pubkeyE = generate_bip340_key_pair()
privkeyF, pubkeyF = generate_bip340_key_pair()

tapleafA = TapLeaf().construct_pk(pubkeyA)
tapleafB = TapLeaf().construct_pk(pubkeyB)
tapleafC = TapLeaf().construct_pk(pubkeyC)
tapleafD = TapLeaf().construct_pk(pubkeyD)
tapleafE = TapLeaf().construct_pk(pubkeyE)
tapleafF = TapLeaf().construct_pk(pubkeyF)

# Assign frequencies to the TapLeaves to generate the desired tree
weightA = 1
weightB = 1
weightC = 1
weightD = 1
weightE = 4
weightF = 8

# Construct TapTree with Huffman constructor
taptree = TapTree()
taptree.key = internal_pubkey
taptree.huffman_constructor([(weightA, tapleafA), (weightB, tapleafB), (weightC, tapleafC), (weightD, tapleafD), (weightE, tapleafE), (weightF, tapleafF)])
print("Taptree descriptor: {}\n".format(taptree.desc))

tapleaves = [("A", tapleafA, 4), \
             ("B", tapleafB, 4), \
             ("C", tapleafC, 4), \
             ("D", tapleafD, 4), \
             ("E", tapleafE, 2), \
             ("F", tapleafF, 1)]

segwit_v1_script, tweak, control_map = taptree.construct()

for leaf_label, tapleaf, depth in tapleaves:
    controlblock = control_map[tapleaf.script]
    print("TapLeaf{} is located at depth {}".format(leaf_label, depth))
    assert int((len(controlblock) - 33)/32) == depth
    
print("Your constructed TapTree is correct!")