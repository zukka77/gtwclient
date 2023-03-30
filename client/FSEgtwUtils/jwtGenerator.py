from jwcrypto import jwk, jwt, jws
import dataclasses
import uuid
import time
import json
from typing import Tuple, TypedDict


@dataclasses.dataclass
class JwtData:
    sub: str
    purpose_of_use: str
    iss: str
    locality: str
    subject_organization_id: str
    subject_organization: str
    aud: str
    patient_consent: bool
    action_id: str
    resource_hl7_type: str
    subject_role: str
    person_id: str
    attachment_hash: str = ""
    jti: str = ""


class VerifyResult(TypedDict):
    header: dict
    payload: dict


class JwtGenerator:
    key: bytes
    cert: str
    data: JwtData

    def __init__(self, key: bytes, cert: str, exp_time_sec=3600):
        self.key = jwk.JWK.from_pem(key)
        self.exp_time_sec = exp_time_sec

        if any(x in cert for x in ["BEGIN CERTIFICATE", "BEGIN PUBLIC KEY"]):
            certpem = list(map(lambda x: x.strip(), cert.splitlines()))
            cert = "".join(certpem[1:-1])
        self.cert = cert
        self.headers = {"alg": "RS256", "typ": "JWT", "x5c": [cert]}

    @staticmethod
    def load_key(path: str) -> bytes:
        with open(path, "rb") as f:
            pemkey = f.read()
        return pemkey

    @staticmethod
    def load_crt(path: str) -> str:
        with open(path, "r", encoding="utf8") as f:
            certpem = list(map(lambda x: x.strip(), f.readlines()))
            certpem = "".join(certpem[1:-1])
        return certpem

    def generate_validation_jwt(self, data: JwtData) -> Tuple[str, str]:
        nowepoch = int(time.time())
        claims = dataclasses.asdict(data)
        claims_auth = {"sub": data.sub, "iss": data.iss, "aud": data.aud}

        claims.update(
            {
                "iat": nowepoch,
                "nbf": nowepoch,
                "exp": nowepoch + self.exp_time_sec,
                "jti": str(uuid.uuid4()),
            }
        )
        claims_auth.update(
            {
                "iat": nowepoch,
                "nbf": nowepoch,
                "exp": nowepoch + self.exp_time_sec,
                "jti": str(uuid.uuid4()),
            }
        )
        # gestione issuer:
        claims["iss"] = "integrity:" + claims["iss"]
        claims_auth["iss"] = "auth:" + claims_auth["iss"]
        token = jwt.JWT(header=self.headers, claims=claims)
        token.make_signed_token(self.key)
        auth_token = jwt.JWT(header=self.headers, claims=claims_auth)
        auth_token.make_signed_token(self.key)
        return (token.serialize(compact=True), auth_token.serialize(compact=True))

    def generate_auth_jwt(self, sub: str, iss: str, aud: str) -> str:
        nowepoch = int(time.time())
        claims_auth = {"sub": sub, "iss": iss, "aud": aud}
        claims_auth.update(
            {
                "iat": nowepoch,
                "nbf": nowepoch,
                "exp": nowepoch + self.exp_time_sec,
                "jti": str(uuid.uuid4()),
            }
        )
        claims_auth["iss"] = "auth:" + claims_auth["iss"]
        auth_token = jwt.JWT(header=self.headers, claims=claims_auth)
        auth_token.make_signed_token(self.key)
        return auth_token.serialize(compact=True)

    @staticmethod
    def verify_token(token: str) -> VerifyResult:
        t = jws.JWS.from_jose_token(token)
        cert = t.jose_header["x5c"][0]
        try:
            pemcert = (
                "-----BEGIN CERTIFICATE-----\n"
                + "\n".join([cert[n : n + 64] for n in range(0, len(cert), 64)])
                + "\n-----END CERTIFICATE-----\n"
            )
            key = jwk.JWK.from_pem(pemcert.encode("utf8"))
        except ValueError:
            pemcert = (
                "-----BEGIN PUBLIC KEY-----\n"
                + "\n".join([cert[n : n + 64] for n in range(0, len(cert), 64)])
                + "\n-----END PUBLIC KEY-----\n"
            )
            key = jwk.JWK.from_pem(pemcert.encode("utf8"))
        t.verify(key)
        res = {
            "header": {k: v.decode("utf8") if type(v) == bytes else v for k, v in t.jose_header.items()},
            "payload": json.loads(t.payload.decode("utf8")),
        }
        return res
