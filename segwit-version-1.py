import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce
from test_framework.messages import CTxInWitness, sha256
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, sign_musig
from test_framework.script import CScript, CScriptOp, hash160, OP_0, OP_2, OP_CHECKMULTISIG, SegwitV0SignatureHash, SIGHASH_ALL, SIGHASH_ALL_TAPROOT, TaprootSignatureHash


### BIP341 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

### taproot outputs can be spent in two ways, key path and script path

### This lesson will create a segwit v1(taproot) address and manually construct a transaction that spends it with bip 341 key path rules

### key paht spending lock the output to a 32 byge public key and unlocks it with a 64/65Bytes signature

# Key pair generation
privkey, pubkey = generate_bip340_key_pair()
print("Pubkey is {}\n".format(pubkey.get_bytes().hex()))

# Create witness program ([32B x-coordinate])
program = pubkey.get_bytes()
print("Witness program is {}\n".format(program.hex()))

# Create (regtest) bech32m address
version = 0x01
### add argument main=True to get mainnet address
address = program_to_witness(version, program)
print("bech32m address is {}".format(address))

# Start node in usual way
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output with helper function
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

### generated regtest address now has balance of 50BTC

### manually construct CTransaction and populate data members just like v0
### We use the create_spending_transaction(node, txid) convenience function

# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}".format(spending_tx))


# Generate the taproot signature hash for signing
# SIGHASH_ALL_TAPROOT is 0x00
sighash = TaprootSignatureHash(spending_tx, [tx.vout[0]], SIGHASH_ALL_TAPROOT, input_index=0)
 
# All schnorr sighashes except SIGHASH_ALL_TAPROOT require
# the hash_type appended to the end of signature
sig = privkey.sign_schnorr(sighash)

print("Signature: {}".format(sig.hex()))

# Construct transaction witness
spending_tx.wit.vtxinwit.append(CTxInWitness([sig]))

print("Spending transaction:\n{}\n".format(spending_tx))
 
# Test mempool acceptance
node.test_transaction(spending_tx)
print("Success!")
test.shutdown()