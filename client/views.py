from django.shortcuts import render
from django import forms
from django.http import HttpRequest
from .FSEgtwUtils import create_pdf_with_attachment, JwtGenerator, JwtData
from django.conf import settings
import requests
import json
from .xml_initial import cda
from .models import *
from .datasets import RUOLO_CHOICES
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID


def get_issuer():
    crt = x509.load_pem_x509_certificate(
        (settings.BASE_DIR/'client_sign').read_bytes())
    iss = crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return iss


class ValidationForm(forms.Form):
    healthDataFormat = forms.ChoiceField(choices=[('CDA', 'CDA')])
    mode = forms.ChoiceField(choices=[('ATTACHMENT', 'ATTACHMENT')])
    activity = forms.ChoiceField(choices=[('VALIDATION', 'VALIDATION')])
    sub = forms.CharField(initial="PROVAX00X00X000Y")
    subject_role = forms.ChoiceField(choices=RUOLO_CHOICES)
    purpose_of_use = forms.ChoiceField(choices=[('TREATMENT', 'TREATMENT')])
    iss = forms.CharField(initial=get_issuer(), disabled=True)
    locality = forms.CharField(initial="201123456")
    subject_organization = forms.CharField(initial="Regione Emilia-Romagna")
    subject_organization_id = forms.CharField(initial="080")
    aud = forms.CharField(
        initial="https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1", disabled=True)
    patient_consent = forms.BooleanField(initial=True, disabled=True)
    action_id = forms.ChoiceField(choices=[("CREATE", "CREATE")])
    resource_hl7_type = forms.CharField(
        initial="('11502-2^^2.16.840.1.113883.6.1')")
    person_id = forms.CharField(
        initial="RSSMRA22A01A399Z^^^&amp;2.16.840.1.113883.2.9.4.3.2&amp;ISO")
    cda = forms.CharField(widget=forms.Textarea(
        attrs={"cols": "120", "rows": "30"}), initial=cda)


def make_request(data, jwt, jwt_auth, pdf):
    VALIDATE_URI = "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/documents/validation"
    s = requests.Session()
    s.cert = str(settings.BASE_DIR/'client_auth')
    s.headers.update({"Accept": "application/json"})
    headers = {"Authorization": "Bearer "+jwt_auth, "FSE-JWT-Signature": jwt}

    res = s.post(VALIDATE_URI,
                 headers=headers,
                 files=[("file", ("cda.pdf", pdf, "application/pdf"))],
                 data=[('requestBody',
                        json.dumps(data)
                        )]
                 )
    return res


def validation(request: HttpRequest):
    jwt = None
    response = None
    jwt_auth = None
    jwt_data = None
    jwt_auth_data = None
    if request.method == 'POST':
        form = ValidationForm(request.POST)
        if form.is_valid():
            jwtData = JwtData(
                action_id=form.cleaned_data['action_id'],
                aud=form.cleaned_data['aud'],
                iss=form.cleaned_data['iss'],
                locality=form.cleaned_data['locality'],
                patient_consent=form.cleaned_data['patient_consent'],
                purpose_of_use=form.cleaned_data['purpose_of_use'],
                resource_hl7_type=form.cleaned_data['resource_hl7_type'],
                sub=form.cleaned_data['sub'],
                subject_organization=form.cleaned_data['subject_organization'],
                subject_organization_id=form.cleaned_data['subject_organization_id'],
                subject_role=form.cleaned_data['subject_role'],
                person_id=form.cleaned_data['person_id']
            )
            data = {
                'activity': form.cleaned_data['activity'],
                'mode': form.cleaned_data['mode'],
                'healthDataFormat': form.cleaned_data['healthDataFormat'],
            }
            key = (settings.BASE_DIR/'client_sign').read_bytes()
            cert = (settings.BASE_DIR/'client_sign').read_text()
            certlines = cert.splitlines()
            cert = '\n'.join(
                certlines[certlines.index('-----BEGIN CERTIFICATE-----'):])
            jwtGenerator = JwtGenerator(key, cert)
            jwt, jwt_auth = jwtGenerator.generate_validation_jwt(jwtData)
            pdf = create_pdf_with_attachment(form.cleaned_data['cda'])
            res = make_request(data, jwt, jwt_auth, pdf)
            response = res
            jwt_data= jwtGenerator.verify_token(jwt)
            jwt_auth_data= jwtGenerator.verify_token(jwt_auth)
    else:
        form = ValidationForm()
    return render(request, 'validation.html',
                  context={'form': form, "jwt": jwt,
                           "jwt_auth": jwt_auth,
                           "response": response,
                           'jwt_data': jwt_data,
                           'jwt_auth_data': jwt_auth_data
                           })
