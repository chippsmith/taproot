import random
from io import BytesIO

import util
from test_framework.address import program_to_witness
from test_framework.key import ECKey, ECPubKey, SECP256K1_ORDER, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, int_or_bytes
from test_framework.messages import COutPoint, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures, musig_digest
from test_framework.script import CScript, CTransaction, OP_RETURN, SIGHASH_ALL_TAPROOT, TaprootSignatureHash, tagged_hash

#First, we commit a contract between Alice and Bob and then demonstrate how this unsafe commitment can be changed.

# Alice generates a key pair
x_key, P_key = generate_key_pair()
print("Private key: {}\nPublic key: {}\n".format(x_key.secret, P_key.get_bytes().hex()))

# Alice generates the tweak from the contract
contract = "Alice agrees to pay 10 BTC to Bob"
t = sha256(contract.encode('utf-8'))
print("Tweak from original contract: {}\n".format(t.hex()))

# Alice tweaks her key pair
Q_key = P_key.tweak_add(t)
q_key = x_key.add(t)
print("Tweaked private key: {}\nTweaked public key: {}\n".format(q_key.secret, Q_key.get_bytes().hex()))

# Alice produces a valid signature for this tweaked public key
msg = sha256(b'I agree to the committed contract')
sig = q_key.sign_schnorr(msg)

# Bob can verify that sig is a valid signature for the public key Q:
verify_sig = Q_key.verify_schnorr(sig, msg)
print("Alice has produced a valid signature for Q: {}".format(verify_sig))

# Alice provides the untweaked public key P to Bob.
# Bob believes he can verify that the signature committed to the tweak t:
verify_tweak = P_key.tweak_add(sha256(contract.encode('utf-8'))) == Q_key
print("The signature appears to commit to '{}': {}".format(contract, verify_tweak))

# However, note that is possible for Alice to modify this insecure commitment without changing the value of pub key Q.
# The committed contract is changed to : Alice agrees to pay 0.1 BTC to Bob


# Alice modifies the contract and produces an alternative tweak
alternative_contract = "Alice agrees to pay 0.1 BTC to Bob"
t2 = sha256(alternative_contract.encode('utf-8'))
print("Tweak from original contract: {}".format(t.hex()))
print("Tweak from modified contract: {}\n".format(t2.hex()))

# Alice modifies her original private key and public key
# x2 = x - t2 + t
x_int = x_key.as_int()
t_int = int.from_bytes(t, "big") 
t2_int = int.from_bytes(t2, "big") 
x2_key, P2_key = generate_key_pair((x_int - t2_int + t_int) % SECP256K1_ORDER)

# Alice can still produce a valid signature for Q
msg2 = sha256(b'I agree to the committed contract')
sig2 = q_key.sign_schnorr(msg2)

# Bob can verify that sig is a valid signature for the public key Q:
verify_sig = Q_key.verify_schnorr(sig, msg)
print("Alice has produced a valid signature for Q: {}".format(verify_sig))

# Alice claims that P2 is the untweaked public key.
# Bob believes he can verify that the signature committed to the tweak t:
verify_tweak = P2_key.tweak_add(sha256(alternative_contract.encode('utf-8'))) == Q_key
print("The signature appears to commit to '{}': {}".format(alternative_contract, verify_tweak))