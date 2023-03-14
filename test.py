import urllib.request

from pycose.keys import EC2Key
from pycose.messages import Sign1Message
import pycose.headers
import rfc3161ng

COSE_LABEL_TST = 258 # temporary, not allocated yet

TEST_TSA_URL = "http://freetsa.org/tsr"
TEST_TSA_CERT_URL = "https://freetsa.org/files/tsa.crt"


def fetch(url):
    return urllib.request.urlopen(url).read()


def timestamp_cose_sign1(sign1_buf: bytes, tsa_url: str, trusted_tsa_certificate: bytes) -> bytes:
    # Decode COSE_Sign1 message.
    msg = Sign1Message.decode(sign1_buf)

    # Extract signature bytes.
    signature = msg.signature

    # Initialize the time-stamp authority.
    rt = rfc3161ng.RemoteTimestamper(tsa_url)
    
    # Time-stamp the signature.
    tst = rt.timestamp(data=signature)

    # Verify the time-stamp token.
    rfc3161ng.check_timestamp(tst, data=signature, certificate=trusted_tsa_certificate)

    # Embed the time-stamp token in the unprotected header.
    msg.uhdr_update({COSE_LABEL_TST: tst})

    # Re-encode the COSE_Sign1 message without re-signing.
    buf = msg.encode(sign=False)

    return buf


def verify_timestamp_in_cose_sign1(sign1_buf: bytes, trusted_tsa_certificate: bytes):
    # Decode COSE_Sign1 message.
    msg = Sign1Message.decode(sign1_buf)

    # Extract signature bytes.
    signature = msg.signature

    # Extract time-stamp token from unprotected header.
    tst = msg.uhdr[COSE_LABEL_TST]
    if isinstance(tst, list):
        raise NotImplementedError("array of time-stamp tokens not supported yet")
    elif not type(tst) == bytes:
        raise RuntimeError("expected bstr or array of bstr")

    # Verify the time-stamp token.
    rfc3161ng.check_timestamp(tst, data=signature, certificate=trusted_tsa_certificate)

    # Return time-stamp.
    return rfc3161ng.get_timestamp(tst)


def test():
    print("Creating COSE_Sign1 message")
    sign1_msg = Sign1Message(
        phdr={ pycose.headers.Algorithm: "ES256" },
        payload="signed message".encode("utf-8")
    )

    print("Generating ephemeral private key to sign COSE_Sign1 message")
    cose_key = EC2Key.generate_key(crv="P_256")

    print("Signing COSE_Sign1 message")
    sign1_msg.key = cose_key
    sign1_buf = sign1_msg.encode(sign=True)
    print(f"Size of COSE message: {len(sign1_buf)} bytes")

    print(f"Time-stamping COSE signature with {TEST_TSA_URL}")
    certificate = fetch(TEST_TSA_CERT_URL)
    sign1_buf = timestamp_cose_sign1(sign1_buf, TEST_TSA_URL, certificate)
    print(f"Size of COSE message (with time-stamp token): {len(sign1_buf)} bytes")

    print("Verifying embedded time-stamp token in COSE_Sign1")
    timestamp = verify_timestamp_in_cose_sign1(sign1_buf, certificate)
    print("Token is valid, signature was created before:")
    print(timestamp)

if __name__ == "__main__":
    test()
