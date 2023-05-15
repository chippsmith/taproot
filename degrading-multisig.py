from io import BytesIO
import random

import util
from test_framework.key import generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1, SECP256K1_ORDER
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, musig_digest, sign_musig
from test_framework.script import TapLeaf, TapTree, TaprootSignatureHash, SIGHASH_ALL_TAPROOT
from test_framework.address import program_to_witness
from test_framework.messages import CTransaction, COutPoint, CTxIn, CTxOut, CTxInWitness
from test_framework.util import assert_equal


'''
Create a derading multisig wallet with the following conditions:
Locking conditions¶

    multisig( 3/3 main wallet key ) - spendable immediately; or
    multisig( 2/3 main wallet keys + 1/2 backup keys ) - spendable after 3 days; or
    multisig( 1/3 main wallet keys + 2/2 backup keys ) - spendable after 10 days.

#### Signers
* **Main wallet keys** - Keys A, B, C
* **Backup keys** - Keys D, E

#### Privacy Requirements
No unused public keys should be revealed during spending.

#### Other considerations
Since the backup keys are stored on simple HSMs, they are not able to interactively co-sign MuSig aggregate signatures.

'''

# Generate main wallet key pairs
main_privkeyA, main_pubkeyA = generate_bip340_key_pair()
main_privkeyB, main_pubkeyB = generate_bip340_key_pair()
main_privkeyC, main_pubkeyC = generate_bip340_key_pair()
main_pubkeys = [main_pubkeyA.get_bytes().hex(),
                main_pubkeyB.get_bytes().hex(), 
                main_pubkeyC.get_bytes().hex()]

print("Main pubkeys: {}\n".format(main_pubkeys))

# Generate back-up wallet key pairs
backup_privkeyD, backup_pubkeyD = generate_bip340_key_pair()
backup_privkeyE, backup_pubkeyE = generate_bip340_key_pair()
backup_pubkeys = [backup_pubkeyD.get_bytes().hex(),
                  backup_pubkeyE.get_bytes().hex()]

print("Backup pubkeys: {}\n".format(backup_pubkeys))

# 3-of-3 main key (MuSig public key)
c_map, musig_ABC = generate_musig_key([main_pubkeyA, main_pubkeyB, main_pubkeyC])
main_privkeyA_c = main_privkeyA.mul(c_map[main_pubkeyA])
main_privkeyB_c = main_privkeyB.mul(c_map[main_pubkeyB])
main_privkeyC_c = main_privkeyC.mul(c_map[main_pubkeyC])
main_pubkeyA_c = main_pubkeyA.mul(c_map[main_pubkeyA])
main_pubkeyB_c = main_pubkeyA.mul(c_map[main_pubkeyB])
main_pubkeyC_c = main_pubkeyA.mul(c_map[main_pubkeyC])

if musig_ABC.get_y()%2 != 0:
    musig_ABC.negate()
    main_privkeyA_c.negate()
    main_privkeyB_c.negate()
    main_privkeyC_c.negate()
    main_pubkeyA_c.negate()
    main_pubkeyB_c.negate()
    main_pubkeyC_c.negate()

print("MuSig pubkey: {}".format(musig_ABC.get_bytes().hex()))

# Tapscripts - 2 main keys & 1 backup key
# Use construct_csa_delay() to construct the tapscript
delay =  3 * 6 * 24
tapscript_2a =  TapLeaf().construct_csa_delay(3, [main_pubkeyA, main_pubkeyB, backup_pubkeyD], delay)
tapscript_2b =  TapLeaf().construct_csa_delay(3, [main_pubkeyA, main_pubkeyB, backup_pubkeyE], delay)
tapscript_2c =  TapLeaf().construct_csa_delay(3, [main_pubkeyA, main_pubkeyC, backup_pubkeyD], delay)
tapscript_2d =  TapLeaf().construct_csa_delay(3, [main_pubkeyA, main_pubkeyC, backup_pubkeyE], delay)
tapscript_2e =  TapLeaf().construct_csa_delay(3, [main_pubkeyB, main_pubkeyC, backup_pubkeyD], delay)
tapscript_2f =  TapLeaf().construct_csa_delay(3, [main_pubkeyB, main_pubkeyC, backup_pubkeyE], delay)

# Tapscripts - 1 main keys & 2 backup keys
long_delay =  10 * 6 * 24
tapscript_3a =  TapLeaf().construct_csa_delay(3, [main_pubkeyA, backup_pubkeyD, backup_pubkeyE], long_delay)
tapscript_3b =  TapLeaf().construct_csa_delay(3, [main_pubkeyB, backup_pubkeyD, backup_pubkeyE], long_delay)
tapscript_3c =  TapLeaf().construct_csa_delay(3, [main_pubkeyC, backup_pubkeyD, backup_pubkeyE], long_delay)

# Set list of backup tapscripts
# Suggestion: Include tapscripts with 3d timelocks first, then those with 10d timelocks
backup_tapscripts =  [tapscript_2a, tapscript_2b, tapscript_2c, tapscript_2d, tapscript_2e, tapscript_2f, tapscript_3a, tapscript_3b, tapscript_3c]
                                
assert len(backup_tapscripts) == 9

# Construct taptree with huffman constructor
tapscript_weights = [(2, tapscript_2a), (2, tapscript_2b), (2, tapscript_2c),
                     (2, tapscript_2d), (2, tapscript_2e), (2, tapscript_2f),
                     (1, tapscript_3a), (1, tapscript_3b), (2, tapscript_3c)]
                                
multisig_taproot = TapTree(key=musig_ABC)
multisig_taproot.huffman_constructor(tapscript_weights)

print("Taproot descriptor {}\n".format(multisig_taproot.desc))

# Derive segwit v1 address
tapscript, taptweak, control_map = multisig_taproot.construct()
taptweak = int.from_bytes(taptweak, 'big')
output_pubkey = musig_ABC.tweak_add(taptweak)
output_pubkey_b = output_pubkey.get_bytes()
segwit_address =  program_to_witness(1, output_pubkey_b)
print("Segwit Address:", segwit_address)

test = util.TestWrapper()
test.setup()

test.nodes[0].generate(101)
balance = test.nodes[0].getbalance()
print("Balance: {}".format(balance))

# Send funds to taproot output.
txid = test.nodes[0].sendtoaddress(address=segwit_address, amount=0.5, fee_rate=25)
print("Funding tx:", txid)

# Deserialize wallet transaction.
tx = CTransaction()
tx_hex = test.nodes[0].getrawtransaction(txid)
tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
tx.rehash()

print(tapscript.hex())

print(tx.vout)

# The wallet randomizes the change output index for privacy
# Loop through the outputs and return the first where the scriptPubKey matches the segwit v1 output
output_index, output = next(out for out in enumerate(tx.vout) if out[1].scriptPubKey == tapscript)
output_value = output.nValue

print("Segwit v1 output is {}".format(output))
print("Segwit v1 output value is {}".format(output_value))
print("Segwit v1 output index is {}".format(output_index))


###Create key path spend
# Construct transaction
spending_tx = CTransaction()

# Populate the transaction version
spending_tx.nVersion = 1

# Populate the locktime
spending_tx.nLockTime = 0

# Populate the transaction inputs
outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint = outpoint)
spending_tx.vin = [spending_tx_in]

print("Spending transaction:\n{}".format(spending_tx))

# Generate new Bitcoin Core wallet address
dest_addr = test.nodes[0].getnewaddress(address_type="bech32")
scriptpubkey = bytes.fromhex(test.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])

# Determine minimum fee required for mempool acceptance
min_fee = int(test.nodes[0].getmempoolinfo()['mempoolminfee'] * 100000000)

# Complete output which returns funds to Bitcoin Core wallet
dest_output = CTxOut(nValue=output_value - min_fee, scriptPubKey=scriptpubkey)
spending_tx.vout = [dest_output]

print("Spending transaction:\n{}".format(spending_tx))


# Negate keys if necessary
output_keyPath = output_pubkey
privKeyA_keyPath = main_privkeyA_c
privKeyB_keyPath = main_privkeyB_c
privKeyC_keyPath = main_privkeyC_c
tweak_keyPath = taptweak

if output_keyPath.get_y() %2  != 0:
    output_keyPath.negate()
    privKeyA_keyPath.negate()
    privKeyB_keyPath.negate()
    privKeyC_keyPath.negate()
    tweak_keyPath = SECP256K1_ORDER - taptweak


# Create sighash for ALL
sighash_musig =  TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT)
 
# Generate individual nonces for participants and an aggregate nonce point
# Remember to negate the individual nonces if necessary
n1 = generate_schnorr_nonce()
n2 = generate_schnorr_nonce()
n3 = generate_schnorr_nonce()
R_agg, negated =  aggregate_schnorr_nonces([n1.get_pubkey(),n2.get_pubkey(),n3.get_pubkey()])

###Why do we not negate R_agg here??
if negated:
    n1.negate()
    n2.negate()
    n3.negate()
    

# Create an aggregate signature.
# Remember to add a factor for the tweak
sA = sign_musig(privKeyA_keyPath, n1, R_agg, output_pubkey, sighash_musig)
sB = sign_musig(privKeyB_keyPath, n2, R_agg, output_pubkey, sighash_musig)
sC = sign_musig(privKeyC_keyPath, n3, R_agg, output_pubkey, sighash_musig)
e = musig_digest(R_agg, output_keyPath, sighash_musig)
sig_agg = aggregate_musig_signatures([sA, sB, sC, e * tweak_keyPath], R_agg)

print("Aggregate signature is {}\n".format(sig_agg.hex()))


### Why is it not verifying???  Only works half time,  Something to do with odd y value
### Now it works
assert output_keyPath.verify_schnorr(sig_agg, sighash_musig)

# Construct transaction witness
spending_tx.wit.vtxinwit.append(CTxInWitness([sig_agg]))
 
print("spending_tx: {}\n".format(spending_tx))

# Test mempool acceptance
spending_tx_str = spending_tx.serialize().hex() 
assert test.nodes[0].testmempoolaccept([spending_tx_str])[0]['allowed']

print("Key path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))

print("Success!")
### now we want to spend using a short delay script
spending_tx = CTransaction()
spending_tx.nVersion = 2
spending_tx.nLockTime = 0
outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint=outpoint, nSequence=delay)
spending_tx.vin = [spending_tx_in]
spending_tx.vout = [dest_output]

sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, scriptpath=True, script= tapscript_2a.script)
witness_elements = []

# Add signatures to the witness
# Remember to reverse the order of signatures  WHY Reverse order?? Script??
sigA = main_privkeyA.sign_schnorr(sighash)
sigB = main_privkeyB.sign_schnorr(sighash)
sigD = backup_privkeyD.sign_schnorr(sighash)


witness_elements = [sigD, sigB, sigA, tapscript_2a.script, control_map[tapscript_2a.script]]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
spending_tx_str = spending_tx.serialize().hex()

# Test timelock
a = test.nodes[0].testmempoolaccept([spending_tx_str])
print(a)

print("Short delay script path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))

test.nodes[0].generate(delay - 1)


test.nodes[0].generate(1)

# Transaction should be accepted now that the timelock is satisfied
a = test.nodes[0].testmempoolaccept([spending_tx_str])
print(a)
assert test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed']


print("Success!")
test.shutdown()