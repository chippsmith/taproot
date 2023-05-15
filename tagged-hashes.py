###http://localhost:8889/notebooks/0.3-tagged-hashes.ipynb
###https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
###For example, without tagged hashing a BIP340 signature could also be valid for a signature scheme where the only difference is that the arguments to the hash function are reordered. Worse, if the BIP340 nonce derivation function was copied or independently created, then the nonce could be accidentally reused in the other scheme leaking the secret key.
###Make sure hashes used in one context cannot be used in another context

from test_framework.script import sha256

### Implement tagged_hash function
### Function takes two inputs tag and data
### Per bip: tagged_hash("TagName", data) = sha256(sha256("TagName") + sha256("TagName") + data)
### tags include BIP0340/aux BIP0340/nonce and BIP0340/challenge, TapLeaf
def tagged_hash(tag, input_data):
    tag_digest = sha256(tag)
    preimage = tag_digest + tag_digest + input_data
    return sha256(preimage)

h = tagged_hash(b'SampleTagName', b'Input data')

###test case
assert h.hex() == "4c55df56134d7f37d3295850659f2e3729128c969b3386ec661feb7dfe29a99c"

print("success")