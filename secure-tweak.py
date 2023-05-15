import random
from io import BytesIO

import util
from test_framework.address import program_to_witness
from test_framework.key import ECKey, ECPubKey, SECP256K1_ORDER, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, int_or_bytes
from test_framework.messages import COutPoint, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures, musig_digest
from test_framework.script import CScript, CTransaction, OP_RETURN, SIGHASH_ALL_TAPROOT, TaprootSignatureHash, tagged_hash


### Pay-to-contract: Tweaking the pubkey with H(P|msg)
### since P occurs inside and outside the hash it isnt possible to solve for a different contract by modifying x# Alice generates a key pair
x_key, P_key = generate_key_pair()
print("Private key: {}\nPublic key: {}\n".format(x_key.secret, P_key.get_bytes().hex()))

# Alice computes the tweak from H(P|msg)
contract = "Alice agrees to pay 10 BTC to Bob"
t = tagged_hash("TapTweak", P_key.get_bytes() + contract.encode('utf-8'))

# Alice tweaks her key pair
Q_key = P_key.tweak_add(t)
q_key = x_key.add(t)
print("Tweaked private key: {}\nTweaked public key: {}\n".format(q_key.secret, Q_key.get_bytes().hex()))

# Alice signs a valid message
msg = sha256(b'I agree to the committed contract')
sig = q_key.sign_schnorr(msg)

# Bob can verify that sig is a valid signature for the public key Q:
verify_sig = Q_key.verify_schnorr(sig, msg)
print("Alice has produced a valid signature for Q: {}".format(verify_sig))

# Alice provides the untweaked public key P to Bob.
# Bob believes he can verify that the signature committed to the tweak t:
verify_tweak = P_key.tweak_add(t) == Q_key
print("The signature commits to '{}': {}".format(contract, verify_tweak))