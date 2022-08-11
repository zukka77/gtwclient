from .pdf import create_pdf,create_pdf_with_attachment

def test_create_pdf():
    pdf=create_pdf()
    assert pdf.startswith('%PDF-')

def test_create_pdf_with_attachment():
    pdf=create_pdf_with_attachment("attached string")
    assert pdf.getvalue().decode('latin-1').startswith('%PDF-')
    pdf=create_pdf_with_attachment("attached string",pdf_text="pdf content")
    assert pdf.getvalue().decode('latin-1').startswith('%PDF-')
