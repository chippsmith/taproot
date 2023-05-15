import util
from io import BytesIO
from hashlib import sha256
from test_framework.key import generate_schnorr_nonce,  SECP256K1_ORDER, ECKey, ECPubKey, generate_key_pair, generate_bip340_key_pair
from test_framework.musig import aggregate_schnorr_nonces, musig_digest, generate_musig_key, sign_musig, aggregate_musig_signatures
from test_framework.script import TapLeaf, TapTree, TaprootSignatureHash, SIGHASH_ALL_TAPROOT
from test_framework.address import program_to_witness
from test_framework.messages import CTransaction, COutPoint, CTxIn, CTxOut, CTxInWitness

### First I want to create a Musig Spend (done)
### Now create backup keys and tapleafs and calculate taproot
### privkey1, pubkey1 = generate_key_pair(sha256(b'key0'))
### 3 main private keys
p1, P1 = generate_bip340_key_pair()
p2, P2 = generate_bip340_key_pair()
p3, P3 = generate_bip340_key_pair()
### Main pubkeys
pubkeys = [P1, P2, P3]

### Backup Keys
p4, P4 = generate_bip340_key_pair()
p5, P5 = generate_bip340_key_pair()
### Backup Pubkeys
backup_pubkeys = [P4, P5]




print("Main pubkeys: {}".format(pubkeys))
print("Backup pubkeys: {}".format(backup_pubkeys))

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

print(f"musig pubkey: {pubkey_agg.get_bytes().hex()}")


# Tapscripts - 2 main keys & 1 backup key
# Use construct_csa_delay() to construct the tapscript
delay =  3 * 6 * 24
tapscript_2a =  TapLeaf().construct_csa_delay(3, [P1, P2, P4], delay)
tapscript_2b =  TapLeaf().construct_csa_delay(3, [P1, P2, P5], delay)
tapscript_2c =  TapLeaf().construct_csa_delay(3, [P1, P3, P4], delay)
tapscript_2d =  TapLeaf().construct_csa_delay(3, [P1, P3, P5], delay)
tapscript_2e =  TapLeaf().construct_csa_delay(3, [P2, P3, P4], delay)
tapscript_2f =  TapLeaf().construct_csa_delay(3, [P2, P3, P5], delay)

# Tapscripts - 1 main keys & 2 backup keys
long_delay =  10 * 6 * 24
tapscript_3a =  TapLeaf().construct_csa_delay(3, [P1, P4, P5], long_delay)
tapscript_3b =  TapLeaf().construct_csa_delay(3, [P2, P4, P5], long_delay)
tapscript_3c =  TapLeaf().construct_csa_delay(3, [P3, P4, P5], long_delay)

backup_tapscripts = [tapscript_2a, tapscript_2b, tapscript_2c, tapscript_2d, tapscript_2e, tapscript_2f, tapscript_3a, tapscript_3b, tapscript_3c]
tapscript_weights = [(2, tapscript_2a), (2, tapscript_2b), (2, tapscript_2c),
                     (2, tapscript_2d), (2, tapscript_2e), (2, tapscript_2f),
                     (1, tapscript_3a), (1, tapscript_3b), (2, tapscript_3c)]


multisig_taproot = TapTree(key=pubkey_agg)
multisig_taproot.huffman_constructor(tapscript_weights)
print("Taproot descriptor {}\n".format(multisig_taproot.desc))

tapscript, taptweak, control_map = multisig_taproot.construct()
taptweak = int.from_bytes(taptweak, 'big')

###add taptweak to musig pubkey
output_pubkey = pubkey_agg.tweak_add(taptweak)
output_pubkey_b = output_pubkey.get_bytes()
segwit_address = program_to_witness(1, output_pubkey_b)
print(f"Segwit v1 address: {segwit_address}")

### set up regtest node to send newly created taproot address some coin
test = util.TestWrapper()
test.setup()
test.nodes[0].generate(101)
balance = test.nodes[0].getbalance()
print("Balance: {}".format(balance))
# Send funds to taproot output.
txid = test.nodes[0].sendtoaddress(address=segwit_address, amount=0.5, fee_rate=25)
print("Funding tx:", txid)

# Deserialize wallet transaction using the class CTransaction and the method deserialize()

tx = CTransaction()
tx_hex = test.nodes[0].getrawtransaction(txid)
tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
tx.rehash()

print(tapscript.hex())

print(f"tx.vout: {tx.vout}")

# The wallet randomizes the change output index for privacy
# Loop through the outputs and return the first where the scriptPubKey matches the segwit v1 output
output_index, output = next(out for out in enumerate(tx.vout) if out[1].scriptPubKey == tapscript)
output_value = output.nValue

### construct transaction
spending_tx = CTransaction()

# need to populate the values in spending tx
spending_tx.nVersion = 1

# Populate the locktime
spending_tx.nLockTime = 0

outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint = outpoint)
spending_tx.vin = [spending_tx_in]
# Generate new Bitcoin Core wallet address
dest_addr = test.nodes[0].getnewaddress(address_type="bech32")
scriptpubkey = bytes.fromhex(test.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])

# Determine minimum fee required for mempool acceptance
min_fee = int(test.nodes[0].getmempoolinfo()['mempoolminfee'] * 100000000)

# Complete output which returns funds to Bitcoin Core wallet
dest_output = CTxOut(nValue=output_value - min_fee, scriptPubKey=scriptpubkey)
spending_tx.vout = [dest_output]


print("Spending transaction:\n{}".format(spending_tx))

### if aggregate pub key after tweak(output_pubkey) y value is odd negate it and the tweak and the privatekey
if output_pubkey.get_y() % 2 != 0:
    output_pubkey.negate()
    p1_c.negate()
    p2_c.negate()
    p3_c.negate()
    taptweak = SECP256K1_ORDER - taptweak

sighash_musig = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT)


# Generate individual nonces for participants and an aggregate nonce point
# Remember to negate the individual nonces if necessary
nonceA = generate_schnorr_nonce()
nonceB = generate_schnorr_nonce()
nonceC = generate_schnorr_nonce()
R_agg, negated = aggregate_schnorr_nonces([nonceA.get_pubkey(), nonceB.get_pubkey(), nonceC.get_pubkey()])
if negated:
    nonceA.negate()
    nonceB.negate()
    nonceC.negate()


s1 = sign_musig(p1_c, nonceA, R_agg, output_pubkey, sighash_musig)
s2 = sign_musig(p2_c, nonceB, R_agg, output_pubkey, sighash_musig)
s3 = sign_musig(p3_c, nonceC, R_agg, output_pubkey, sighash_musig)
e = musig_digest(R_agg, output_pubkey, sighash_musig)
sig_agg = aggregate_musig_signatures([s1, s2, s3, e * taptweak],R_agg )

print("Aggregate signature is {}\n".format(sig_agg.hex()))


assert output_pubkey.verify_schnorr(sig_agg, sighash_musig)

print("Success! Signature verifies against aggregate pubkey")


# Lets spend using short delay script 2a
# We need to sign with private key A and B and backup key D per the script

spending_tx = CTransaction()
spending_tx.nVersion = 2
spending_tx.nLockTime = 0
outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint=outpoint, nSequence=delay)
spending_tx.vin = [spending_tx_in]
spending_tx.vout = [dest_output]

sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, scriptpath=True, script= tapscript_2a.script)

sig1 = p1.sign_schnorr(sighash)
sig2 = p2.sign_schnorr(sighash)
sig4 = p4.sign_schnorr(sighash)

###remember to list signatures in reverse order 
witness_elements= [sig4, sig2, sig1, tapscript_2a.script, control_map[tapscript_2a.script] ]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
spending_tx_str = spending_tx.serialize().hex()

# generate block to test transaction is valid at correct block height

test.nodes[0].generate(delay - 1)
message = test.nodes[0].testmempoolaccept([spending_tx_str])
print(message)
# assert that allowed portion of json says false because not enough blocks have passed
assert not test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed']

test.nodes[0].generate(1)
message = test.nodes[0].testmempoolaccept([spending_tx_str])
print(message)
# assert that allowed portion of json says true because enough blocks have passed for a valid transaction
assert test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed']

test.shutdown()