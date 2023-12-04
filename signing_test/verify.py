from hashlib import sha256

import ecdsa


def verify(public_key, signature, message) -> bool:
    vk = ecdsa.VerifyingKey.from_string(
        bytes.fromhex(public_key), curve=ecdsa.NIST256p, hashfunc=sha256
    )
    try:
        vk.verify(signature, message, sigdecode=ecdsa.util.sigdecode_der)
        print("Signature is valid.")
        return True
    except ecdsa.BadSignatureError:
        print("Signature is invalid.")
        return False


if __name__ == "__main__":
    # message = input("Enter message: ").encode()
    # public_key = input("Enter public key: ")
    # r = int(input("Enter r: "), 16)
    # s = int(input("Enter s: "), 16)
    message = b"3030303030303030303030303030303030303030303030303030303030303030"
    public_key = "032686c1e58a08b329720951e6617be660ba207d578320179a1526749f5cfaaa7b"
    r = int("c0bc9c8af73319a77ea28b335e8fbdf7fe6d7ee4ac6e274d29a8646471975e95", 16)
    s = int("3fbd53fe84c332803507e5e2078fa9a5b6434564c3133210f874b15b2bb10ada", 16)
    signature = ecdsa.util.sigencode_der(r, s, order=ecdsa.NIST256p.order)
    verify(public_key, signature, message)
