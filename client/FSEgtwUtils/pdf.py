from fpdf import FPDF
from pikepdf import Pdf, AttachedFileSpec
from io import BytesIO

def create_pdf(text="Test PDF")->str:
    pdf=FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size = 15)
    for l in text.splitlines():
        pdf.cell(0,10,l,ln=1)
    return pdf.output(dest="S")

def create_pdf_with_attachment(attachment:str=None,attachment_name="cda.xml",pdf_text:str=None)->BytesIO:
    if pdf_text:
        pdf=create_pdf(pdf_text)
    else:
        pdf=create_pdf()
    pdfio=BytesIO(pdf.encode('latin-1'))
    pdf=Pdf.open(pdfio)
    pdf.attachments[attachment_name] = AttachedFileSpec(pdf,data=attachment.encode('utf8'),mime_type="text/xml",filename=attachment_name)
    outpdf=BytesIO()
    pdf.save(outpdf)
    pdfio.close()
    outpdf.seek(0)
    return outpdf
