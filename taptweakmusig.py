
import random
from io import BytesIO

import util
from test_framework.address import program_to_witness
from test_framework.key import ECKey, ECPubKey, SECP256K1_ORDER, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, int_or_bytes
from test_framework.messages import COutPoint, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures, musig_digest
from test_framework.script import CScript, CTransaction, OP_RETURN, SIGHASH_ALL_TAPROOT, TaprootSignatureHash, tagged_hash
# Generate a key pair
privkey, pubkey = generate_bip340_key_pair()

print("Private key: {}\nPublic key: {}\n".format(privkey.secret, pubkey.get_bytes().hex()))

# Generate a random tweak scalar 0 < t < SECP256K1_ORDER and derive its associated tweak point
tweak = random.randrange(1, SECP256K1_ORDER)
tweak_private = ECKey().set(tweak)
tweak_point = tweak_private.get_pubkey()
print("Tweak scalar: {}\nTweak point: {}\n".format(tweak_private.secret, tweak_point.get_bytes().hex()))

# Derive the tweaked private key and public key
privkey_tweaked = privkey + tweak_private
pubkey_tweaked = pubkey + tweak_point
print("Tweaked private key: {}\nTweaked pubkey: {}\n".format(privkey_tweaked.secret, pubkey_tweaked.get_bytes().hex()))

# Sign the message with tweaked key pair and verify the signature
msg = sha256(b'msg')
sig = privkey_tweaked.sign_schnorr(msg)
assert pubkey_tweaked.verify_schnorr(sig, msg)
print("Success!")