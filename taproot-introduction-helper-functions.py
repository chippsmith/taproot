import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness
from test_framework.script import SegwitV0SignatureHash, SIGHASH_ALL, hash160, get_p2pkh_script


### This does the same thing as taproot-introduction but with helper functions

# Generate a new key pair
privkey, pubkey = generate_key_pair()
print("Pubkey: {}\n".format(pubkey.get_bytes(bip340=False).hex()))

# Get the hash160 of the public key for the witness program
# Note that the function 'get_bytes(bip340=False)' is used to get the compressed DER encoding of the public key needed for 
# segwit v0.
program = hash160(pubkey.get_bytes(bip340=False))
print("Witness program: {}\n".format(program.hex()))

# Create (regtest) bech32 address
version = 0x00
address = program_to_witness(version, program)
print("bech32 address: {}".format(address))

# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}\n".format(spending_tx))

# Sign the spending transaction and append the witness
sighash = SegwitV0SignatureHash(script=get_p2pkh_script(program),
                                txTo=spending_tx,
                                inIdx=0,
                                hashtype=SIGHASH_ALL,
                                amount=100_000_000)
sig = privkey.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')
spending_tx.wit.vtxinwit.append(CTxInWitness([sig, pubkey.get_bytes(bip340=False)]))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")
test.shutdown()