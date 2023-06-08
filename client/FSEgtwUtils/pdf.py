from fpdf import FPDF
from pikepdf import Pdf, AttachedFileSpec
from io import BytesIO
from typing import BinaryIO
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko import keys
from pyhanko_certvalidator.registry import SimpleCertificateStore
import datetime
from typing import Optional


def create_pdf(text="Test PDF") -> bytearray:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=15)
    for line in text.splitlines():
        pdf.cell(0, 10, line, ln=1)
    # typing is wrong
    # see https://pyfpdf.readthedocs.io/en/latest/reference/output/index.html must encode
    return pdf.output(dest="S").encode("latin-1")


def create_pdf_with_attachment(attachment: str, attachment_name="cda.xml", pdf_text: Optional[str] = None) -> BytesIO:
    if pdf_text:
        pdf = create_pdf(pdf_text)
    else:
        pdf = create_pdf()
    pdfio = BytesIO(pdf)
    pdf = Pdf.open(pdfio)
    pdf.attachments[attachment_name] = AttachedFileSpec(
        # mypy typing is wrong
        pdf,
        data=attachment.encode("utf8"),
        description="CDA2",
        filename=attachment_name,
        mime_type="text/xml",
        creation_date=str(datetime.datetime.now()),
        mod_date=str(datetime.datetime.now()),
    )
    outpdf = BytesIO()
    pdf.save(outpdf)
    pdfio.close()
    outpdf.seek(0)
    return outpdf


def sign_pdf(cert: str, key: str, pdf: BinaryIO, key_pwd: Optional[bytes] = None) -> BytesIO:
    cert_data = list(keys.load_certs_from_pemder_data(cert.encode("utf-8")))[0]
    key_data = keys.load_private_key_from_pemder_data(key.encode("utf-8"), passphrase=key_pwd)
    cms_signer = signers.SimpleSigner(
        signing_key=key_data, signing_cert=cert_data, cert_registry=SimpleCertificateStore()
    )
    pdf.seek(0)
    w = IncrementalPdfFileWriter(pdf)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name="Signature1"),
        signer=cms_signer,
    )
    return out
