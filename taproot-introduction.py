import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness
from test_framework.script import SegwitV0SignatureHash, SIGHASH_ALL, hash160, get_p2pkh_script

### This chapter demonstrates the transaction sequence in full detail. Future chapters follow the same steps, but use convenience functions to abstract away the low-level details.

privkey, pubkey = generate_key_pair()
# Get the hash160 of the public key for the witness program
# Note that the function 'get_bytes(bip340=False)' is used to get the compressed DER encoding of the public key needed for 
# segwit v0.
program = hash160(pubkey.get_bytes(bip340=False))
# Create (regtest) bech32 address
version = 0x00

### add third argurment to function main=true for mainnet address
address = program_to_witness(version, program)
print(address)

### start bitcoin test wrapper with default values including number of nodes = 1
test = util.TestWrapper()

test.setup()

###name the one and only node, "node"

node = test.nodes[0]

### node has all the rpc functions available to it.
### For example:

version = node.getnetworkinfo()['subversion']
print("\nClient version is {}\n".format(version))

# Generate 101 blocks(balance from mining cannot be spent until after 100 blocks have past)
# node helper function genrate can generate blocks
node.generate(101)
# rpc call get balance
balance = node.getbalance()
print("Balance: {}\n".format(balance))

# rpc call listunspent  [-1][txid] parses json to get next to last txid or only txid
unspent_txid = node.listunspent(1)[-1]["txid"]
inputs = [{"txid": unspent_txid, "vout": 0}]

# Create a raw transaction sending 1 BTC to the address and then sign it.
# rpc createrawtransaction takes two args, a lits of inputs and a lits of outputs
tx_hex = node.createrawtransaction(inputs=inputs, outputs=[{address: 1}])
res = node.signrawtransactionwithwallet(hexstring=tx_hex)

# parses tx_hex json return and gets just the hex
tx_hex = res["hex"]

# Send the raw transaction. We haven't created a change output,
# so maxfeerate must be set to 0 to allow any fee rate.
txid = node.sendrawtransaction(hexstring=tx_hex, maxfeerate=0)
print("Transaction {}, output 0\nsent to {}".format(txid, address))

### always shutdown the test at end of program


### we created a segwit v0 address on regtest and sent 50 bitcoin to it from our testwrapper node

### now we can manually construct a transaction and send it back
### we use class CTransaction and populate the data members 
    #nVersion
    #nLocktime
    #tx_vin (list of CTxIn objects)
    #tx_vout (list of CTxOut objects)

spending_tx = CTransaction()
spending_tx.nVersion = 1
spending_tx.nLockTime = 0

# transaction inx are a list of CTxIn which takes a COutPoint class as argurment
outpoint = COutPoint(int(txid, 16), 0)
spending_tx_in = CTxIn(outpoint)
spending_tx.vin = [spending_tx_in]

# we need a new address form out regtest node so we rpc call getnewaddress
dest_addr = node.getnewaddress(address_type="bech32")
# and pull thte scriptpubkey form the json
scriptpubkey = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])

# Complete output which returns 0.5 BTC to Bitcoin Core wallet
amount_sat = int(0.5 * 100_000_000)
dest_output = CTxOut(nValue=amount_sat, scriptPubKey=scriptpubkey)
spending_tx.vout = [dest_output]

print("Spending transaction:\n{}".format(spending_tx))


# Now we need to sign the transaction
# We can use SegwitV0SignatureHash class for this and instantiate it with scirp, txTo, inIdx, hashtype, and amount values

sighash = SegwitV0SignatureHash(script=get_p2pkh_script(program),
                                txTo=spending_tx,
                                inIdx=0,
                                hashtype=SIGHASH_ALL,
                                amount=100_000_000)

# Sign using ECDSA and append the SIGHASH byte
# TODO: find out where "latin-1" comes from
sig = privkey.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')

# For a P2WPKH, the witness field is the signature and pubkey
# We can use the CTxInWitness class which takes the sig and pubkey as arguments
witness = CTxInWitness([sig, pubkey.get_bytes(bip340=False)])

## then we append the witness to the vtxinwit portion of the witness portion of the spending transaction
spending_tx.wit.vtxinwit.append(witness)

print("Spending transaction:\n{}\n".format(spending_tx))

# Serialize signed transaction for broadcast
spending_tx_str = spending_tx.serialize().hex()


# Test mempool acceptance
assert node.testmempoolaccept(rawtxs=[spending_tx_str], maxfeerate=0)[0]['allowed']
print("Success!")



test.shutdown()
