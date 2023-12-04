from fastecdsa import curve, ecdsa, encoding, keys
import binascii

m = "3030303030303030303030303030303030303030303030303030303030303030"
public_keys = keys.get_public_keys_from_sig(
    (
        int("31cfe39ee38fad8296cc0f98ab44266a7ef2dab4c66ea8a24635c92be3a797ec", 16),
        int("67dd9f2195f3fa1fafb1ee1c12f983aff15c42be9491b688d615813de372e541", 16),
    ),
    m,
    curve.P256,
)

for i, public_key in enumerate(public_keys):
    print(public_key)
    keys.export_key(public_key, curve=curve.P256, filepath=f"{i}.pem")

compressed_key_hex = (
    "02b70df12e4ae25619ac2310970f28be8dc66818cabaaae2f893082f0a0351e37c"
)
compressed_key_bytes = binascii.unhexlify(compressed_key_hex)

prefix_byte = compressed_key_bytes[0]
x_bytes = compressed_key_bytes[1:]

print("Prefix Byte:", binascii.hexlify(bytes([prefix_byte])).decode())
print("X-coordinate:", binascii.hexlify(x_bytes).decode())
