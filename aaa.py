from test_framework.key import generate_key_pair
from hashlib import sha256

privkey2, pubkey2 = generate_key_pair(sha256(b'key1'))
