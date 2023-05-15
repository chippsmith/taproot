import random
from io import BytesIO

import util
from test_framework.address import program_to_witness
from test_framework.key import ECKey, ECPubKey, SECP256K1_ORDER, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, int_or_bytes
from test_framework.messages import COutPoint, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures, musig_digest
from test_framework.script import CScript, CTransaction, OP_RETURN, SIGHASH_ALL_TAPROOT, TaprootSignatureHash, tagged_hash

### linear property of bip340 means we can encode a commitment in a public key

### Tweaking a public Key

### Tweaking a key pair and confirming the signature is valid

# Generate a key pair, bip340 keypair confirm y value is not negative
privkey, pubkey = generate_bip340_key_pair()

# Generate a random tweak scalar 0 < t < SECP256K1_ORDER and derive its associated tweak point
tweak = random.randrange(1, SECP256K1_ORDER)

tweak_private_key = ECKey().set(tweak)
tweak_public_key = tweak_private_key.get_pubkey()

privkey_tweaked = privkey + tweak_private_key
pubkey_tweaked = pubkey + tweak_public_key

msg = sha256(b"I will send you bitcoin")

### sign msg with tweaked priv key
sig = privkey_tweaked.sign_schnorr(msg)

### verify thay the tweaked pubkey and signature can be verified with that message
assert pubkey_tweaked.verify_schnorr(sig, msg)
print("Success")