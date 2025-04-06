import base64
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt


def create_dpop_jwt(
    url: str,
    method: str,
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
) -> str:
    jwk = public_key_to_jwk(public_key)
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk,
    }

    payload = {
        "htu": url,
        "htm": method.upper(),
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(payload, private_key, algorithm="ES256", headers=header)
    return token


def public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> dict:
    numbers = public_key.public_numbers()
    x = base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).rstrip(b"=").decode("utf-8")
    y = base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).rstrip(b"=").decode("utf-8")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    }
