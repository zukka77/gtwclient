from .jwtGenerator import JwtGenerator, JwtData
from jwcrypto import jwk
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
import datetime
from tempfile import NamedTemporaryFile
from pytest import fixture
from typing import NamedTuple


class Keys(NamedTuple):
    priv: bytes
    pub: bytes
    pub_str: str


class Certs(NamedTuple):
    key_path: str
    crt_path: str


@fixture(scope="session")
def test_keys() -> Keys:
    """
    Creates temporary test RSA keys
    """
    key = jwk.JWK.generate(kty="RSA", size=2048)
    pem_priv_key = key.export_to_pem(private_key=True, password=None)
    pem_pub_key = key.export_to_pem(private_key=False, password=None)
    # NO BEGIN/END
    pem_pub_str = "".join(list(map(lambda x: x.strip(), pem_pub_key.decode("utf-8").splitlines()))[1:-1])
    return Keys(priv=pem_priv_key, pub=pem_pub_key, pub_str=pem_pub_str)


@fixture(scope="session")
def file_certs() -> Certs:
    """
    Creates temporary test x509 self signed certifcate
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    with NamedTemporaryFile(mode="wb", delete=False) as kf:
        kf.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "TEST"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow()
            + datetime.timedelta(days=10)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(key, hashes.SHA256())
    )
    with NamedTemporaryFile(mode="wb", delete=False) as cf:
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
    print("cert file key:{kf.name} crt:{cf.name}")
    yield Certs(key_path=kf.name, crt_path=cf.name)
    import os

    os.unlink(kf.name)
    os.unlink(cf.name)


def test_jwt_generator(test_keys: Keys, file_certs: Certs):
    jwt_generators = [
        JwtGenerator(key=test_keys.priv, cert=test_keys.pub.decode("utf8")),
        JwtGenerator(key=test_keys.priv, cert=test_keys.pub_str),
        JwtGenerator(key=JwtGenerator.load_key(file_certs.key_path), cert=JwtGenerator.load_crt(file_certs.crt_path)),
    ]
    for jwt_generator in jwt_generators:
        data = JwtData(
            action_id="action_id",
            attachment_hash="attachment_hash",
            aud="aud",
            iss="iss",
            jti="jti",
            locality="locality",
            patient_consent=True,
            person_id="person_id",
            purpose_of_use="pou",
            resource_hl7_type="rhl7t",
            sub="sub",
            subject_organization="s_org",
            subject_organization_id="s_org_id",
            subject_role="s_role",
        )
        jwt = jwt_generator.generate_validation_jwt(data)
        print(f"{jwt[1]}")
        assert jwt[0]
        assert jwt[1]
        data = jwt_generator.verify_token(jwt[0])
        assert data["header"]
        assert data["payload"]
        data = jwt_generator.verify_token(jwt[1])
        assert data["header"]
        assert data["payload"]
        jwt = jwt_generator.generate_auth_jwt(aud="aud", iss="iss", sub="sub")
        data = jwt_generator.verify_token(jwt)
        assert data["header"]
        assert data["payload"]
