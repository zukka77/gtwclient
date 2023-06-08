from fpdf import FPDF
from pikepdf import Pdf, AttachedFileSpec
from io import BytesIO
from typing import BinaryIO
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko import keys


def create_pdf(text="Test PDF") -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=15)
    for line in text.splitlines():
        pdf.cell(0, 10, line, ln=1)
    return pdf.output(dest="S")


def create_pdf_with_attachment(attachment: str = None, attachment_name="cda.xml", pdf_text: str = None) -> BinaryIO:
    if pdf_text:
        pdf = create_pdf(pdf_text)
    else:
        pdf = create_pdf()
    pdfio = BytesIO(pdf.encode("latin-1"))
    pdf = Pdf.open(pdfio)
    pdf.attachments[attachment_name] = AttachedFileSpec(
        pdf, data=attachment.encode("utf8"), mime_type="text/xml", filename=attachment_name
    )
    outpdf = BytesIO()
    pdf.save(outpdf)
    pdfio.close()
    outpdf.seek(0)
    return outpdf


def sign_pdf(cert: str, key: str, pdf: BinaryIO, key_pwd: bytes = None) -> BinaryIO:
    cert = list(keys.load_certs_from_pemder_data(cert.encode("utf-8")))[0]
    key = keys.load_private_key_from_pemder_data(key.encode("utf-8"), passphrase=key_pwd)
    cms_signer = signers.SimpleSigner(signing_key=key, signing_cert=cert, cert_registry=None)
    pdf.seek(0)
    w = IncrementalPdfFileWriter(pdf)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name="Signature1"),
        signer=cms_signer,
    )
    return out
