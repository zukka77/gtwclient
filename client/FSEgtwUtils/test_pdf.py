from .pdf import create_pdf, create_pdf_with_attachment

_PDF_STRING = "%PDF-"


def test_create_pdf():
    pdf = create_pdf()
    assert pdf.startswith(_PDF_STRING)


def test_create_pdf_with_attachment():
    pdf = create_pdf_with_attachment("attached string")
    assert pdf.getvalue().decode("latin-1").startswith(_PDF_STRING)
    pdf = create_pdf_with_attachment("attached string", pdf_text="pdf content")
    assert pdf.getvalue().decode("latin-1").startswith(_PDF_STRING)
