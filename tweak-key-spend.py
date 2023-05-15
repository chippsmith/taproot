import random
from io import BytesIO

import util
from test_framework.address import program_to_witness
from test_framework.key import ECKey, ECPubKey, SECP256K1_ORDER, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, int_or_bytes
from test_framework.messages import COutPoint, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures, musig_digest
from test_framework.script import CScript, CTransaction, OP_RETURN, SIGHASH_ALL_TAPROOT, TaprootSignatureHash, tagged_hash

# Example key pair
privkey = ECKey().set(102118636618570133408735518698955378316807974995033705330357303547139065928052)
internal_pubkey = privkey.get_pubkey()

if internal_pubkey.get_y()%2 != 0:
    privkey.negate()
    internal_pubkey.negate()

# Example tweak
taptweak = bytes.fromhex('2a2fb476ec9962f262ff358800db0e7364287340db73e5e48db36d1c9f374e30')

# Tweak the private key
# Method: ECKey.add()
tweaked_privkey = privkey.add(taptweak)

# Tweak the public key
# Method: use tweak_add()
taproot_pubkey =  internal_pubkey.tweak_add(taptweak)
taproot_pubkey_b =  taproot_pubkey.get_bytes()

# Derive the bech32 address
# Use program_to_witness(version_int, pubkey_bytes)
address =  program_to_witness(0x01, taproot_pubkey_b)

assert address == "bcrt1pjnux0f7037ysqv2aycfntus0t606sjyu0qe2xqewlmhulpdujqeq2z4st9"
print("Success! Address: {}".format(address))

# Start regtest node as usual 
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}".format(spending_tx))

# Sign transaction with tweaked private key
# Method: TaprootSignatureHash(tx, output_list, hash_type=int, input_index=int, scriptpath=bool)
sighash =  TaprootSignatureHash(spending_tx, [tx.vout[0]], 0x0,0, False)
sig =  tweaked_privkey.sign_schnorr(sighash)

# Add witness to transaction
spending_tx.wit.vtxinwit.append(CTxInWitness([sig]))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")

test.shutdown()