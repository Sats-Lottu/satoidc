import ecdsa
from bech32 import bech32_encode, convertbits


def url_encode(url: str) -> str:
    """
    Encode a URL without validating it first and return a bech32 LNURL string.
    """
    try:
        bech32_data = convertbits(url.encode("utf-8"), 8, 5, True)
        assert bech32_data
        lnurl = bech32_encode("lnurl", bech32_data)
    except UnicodeEncodeError:  # pragma: nocover
        raise Exception

    return lnurl.upper()


def verify(k1: str, key: str, sig: str) -> True:
    k1 = bytes.fromhex(k1)
    key = bytes.fromhex(key)
    sig = bytes.fromhex(sig)

    vk = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.SECP256k1)
    try:
        return vk.verify_digest(sig, k1, sigdecode=ecdsa.util.sigdecode_der)
    except ecdsa.keys.BadSignatureError:
        return False
