from hashlib import sha256

import ecdsa


def verify(public_key, signature_r, signature_s, message) -> bool:
    vk = ecdsa.VerifyingKey.from_string(
        bytes.fromhex(public_key), curve=ecdsa.SECP256k1, hashfunc=sha256
    )  # the default is sha1
    try:
        vk.verify(bytes.fromhex(signature_r + signature_s), message)
        print("Signature is valid.")
        return True
    except ecdsa.BadSignatureError:
        print("Signature is invalid.")
        return False


if __name__ == "__main__":
    message = input("Enter message: ").encode()
    public_key = input("Enter public key: ")
    signature_r = input("Enter signature_r: ")
    signature_s = input("Enter signature_s: ")
    print(verify(public_key, signature_r, signature_s, message))
