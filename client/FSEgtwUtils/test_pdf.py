from .pdf import create_pdf, create_pdf_with_attachment, sign_pdf
from pytest import fixture
from jwcrypto import jwk
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from pyhanko import keys
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
import os

_PDF_STRING = "%PDF-"


@fixture(scope="session")
def test_cert(hostname="localhost") -> tuple[str, str, str]:
    """Generates CA end sign a certificate for hostname.
    Code inspired from:
    https://gist.github.com/bloodearnest/9017111a313777b9cce5
    """
    # Copyright 2018 Simon Davy
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.

    # WARNING: the code in the gist generates self-signed certs, for the purposes of testing in development.
    # Do not use these certs in production, or You Will Have A Bad Time.
    #
    # Caveat emptor
    #

    # Generate ca key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname + "ca")])

    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname + "ca")]

    san = x509.SubjectAlternativeName(alt_names)

    basic_contraints = x509.BasicConstraints(ca=True, path_length=1)
    now = datetime.utcnow()
    cacert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cacert_pem = cacert.public_bytes(encoding=serialization.Encoding.PEM)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    alt_names = [x509.DNSName(hostname)]

    san = x509.SubjectAlternativeName(alt_names)
    basic_contraints = x509.BasicConstraints(ca=False, path_length=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(cacert.issuer)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        # Make key good for digital signature
        .add_extension(
            x509.KeyUsage(
                content_commitment=True,
                digital_signature=True,
                key_agreement=False,
                key_encipherment=False,
                key_cert_sign=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=False,
                data_encipherment=False,
            ),
            True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return (cert_pem.decode("utf-8"), key_pem.decode("utf-8"), cacert_pem.decode("utf-8"))


def test_create_pdf():
    pdf = create_pdf()
    assert pdf.startswith(_PDF_STRING)


def test_create_pdf_with_attachment():
    pdf = create_pdf_with_attachment("attached string")
    assert pdf.getvalue().decode("latin-1").startswith(_PDF_STRING)
    pdf = create_pdf_with_attachment("attached string", pdf_text="pdf content")
    assert pdf.getvalue().decode("latin-1").startswith(_PDF_STRING)


def test_sign_pdf(test_cert):
    pdf = create_pdf_with_attachment("attached string", pdf_text="pdf content")
    signed_pdf = sign_pdf(test_cert[0], test_cert[1], pdf)
    assert signed_pdf.getvalue().decode("latin-1").startswith(_PDF_STRING)
    if os.environ.get("DUMP_FILES"):
        import pathlib

        pathlib.Path("signed_pdf.pdf").write_bytes(signed_pdf.getvalue())
        pathlib.Path("crt").write_text(test_cert[0], encoding="utf-8")
        pathlib.Path("cacrt").write_text(test_cert[2], encoding="utf-8")
        pathlib.Path("key").write_text(test_cert[1], encoding="utf-8")
    root_cert = list(keys.load_certs_from_pemder_data(test_cert[2].encode("utf-8")))[0]
    vc = ValidationContext(trust_roots=[root_cert])
    r = PdfFileReader(signed_pdf)
    sig = r.embedded_signatures[0]
    status = validate_pdf_signature(sig, vc)
    print(status.pretty_print_details())
    assert status.valid == True
