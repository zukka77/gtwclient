from datetime import datetime
from pprint import pprint
from uuid import uuid4
from django.shortcuts import render
from django import forms
from django.http import HttpRequest
from .FSEgtwUtils import create_pdf_with_attachment, JwtGenerator, JwtData
from django.conf import settings
import requests
import json
from .xml_initial import cda
from .datasets import ASSETTO_ORGNIZZATIVO_CHOICES, ATTIVITA_CLINICA_CHOICES, REGOLE_DI_ACCESSO_CHOICES, RUOLO_CHOICES, STRUTTURA_CHOICES, TIPO_DOCUMENTO_ALTO_CHOICES
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
import hashlib

def get_issuer():
    crt = x509.load_pem_x509_certificate(
        (settings.BASE_DIR/'client_sign').read_bytes())
    iss = crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return iss


class ValidationForm(forms.Form):
    # PARAMETRY BODY
    healthDataFormat = forms.ChoiceField(choices=[('CDA', 'CDA')])
    mode = forms.ChoiceField(choices=[('ATTACHMENT', 'ATTACHMENT')])
    activity = forms.ChoiceField(choices=[('VALIDATION', 'VALIDATION')])
    #PARAMETRI JWT
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

class PublicationForm(forms.Form):
    # PARAMETRY BODY
    workflowInstanceId = forms.CharField(required=False)
    healthDataFormat = forms.ChoiceField(choices=[('CDA', 'CDA')])
    mode = forms.ChoiceField(choices=[('ATTACHMENT', 'ATTACHMENT')])
    tipologiaStruttura = forms.ChoiceField(choices=STRUTTURA_CHOICES)
    attiCliniciRegoleAccesso = forms.MultipleChoiceField(choices=REGOLE_DI_ACCESSO_CHOICES,required=False)
    identificativoDoc = forms.CharField(initial=str(uuid4()))
    identificativoRep = forms.CharField(initial=str(uuid4()))
    tipoDocumentoLivAlto = forms.ChoiceField(choices=TIPO_DOCUMENTO_ALTO_CHOICES)
    assettoOrganizzativo = forms.ChoiceField(choices=ASSETTO_ORGNIZZATIVO_CHOICES)
    dataInizioPrestazione = forms.DateTimeField(initial=datetime.now,required=False)
    dataFinePrestazione = forms.DateTimeField(initial=datetime.now,required=False)
    conservazioneANorma = forms.BooleanField(initial=False,required=False)
    tipoAttivitaClinica = forms.ChoiceField(choices=ATTIVITA_CLINICA_CHOICES)
    identificativoSottomissione = forms.CharField(initial=str(uuid4()))
    priorita = forms.BooleanField(required=False)
    # PARAMETRI JWT
    sub = forms.CharField(initial="PROVAX00X00X000Y")
    subject_role = forms.ChoiceField(choices=RUOLO_CHOICES)
    subject_organization = forms.CharField(initial="Regione Emilia-Romagna")
    subject_organization_id = forms.CharField(initial="080")
    purpose_of_use = forms.ChoiceField(choices=[('TREATMENT', 'TREATMENT')])
    iss = forms.CharField(initial=get_issuer(), disabled=True)
    locality = forms.CharField(initial="201123456")
    aud = forms.CharField(
        initial="https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1", disabled=True)
    patient_consent = forms.BooleanField(initial=True, disabled=True)
    action_id = forms.ChoiceField(choices=[("CREATE", "CREATE")])
    resource_hl7_type = forms.CharField(
        initial="('11502-2^^2.16.840.1.113883.6.1')")
    person_id = forms.CharField(
        initial="RSSMRA22A01A399Z^^^&amp;2.16.840.1.113883.2.9.4.3.2&amp;ISO")
    #REFERTO CDA
    cda = forms.CharField(widget=forms.Textarea(
        attrs={"cols": "120", "rows": "30"}), initial=cda)
    
    @staticmethod
    def get_body_parameters():
        return [
                "workflowInstanceId",
                "healthDataFormat",
                "mode",
                "tipologiaStruttura",
                "attiCliniciRegoleAccesso",
                "identificativoDoc",
                "identificativoRep",
                "tipoDocumentoLivAlto",
                "assettoOrganizzativo",
                "dataInizioPrestazione",
                "dataFinePrestazione",
                "conservazioneANorma",
                "tipoAttivitaClinica",
                "identificativoSottomissione",
                "priorita",
        ]

def make_validation_request(data, jwt, jwt_auth, pdf):
    VALIDATION_URL = "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/documents/validation"
    return make_request(VALIDATION_URL,data,jwt,jwt_auth,pdf)


def make_publication_request(data, jwt, jwt_auth, pdf):
    PUBLICATION_URL = "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/documents/"
    return make_request(PUBLICATION_URL,data,jwt,jwt_auth,pdf)

def make_request(url,data, jwt, jwt_auth, pdf):
    s = requests.Session()
    s.cert = str(settings.BASE_DIR/'client_auth')
    s.headers.update({"Accept": "application/json"})
    headers = {"Authorization": "Bearer "+jwt_auth, "FSE-JWT-Signature": jwt}

    res = s.post(url,
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
            #save data in session
            for k in form.fields.keys():
                request.session[k]=form.cleaned_data[k]
            jwt_data = JwtData(
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
            jwt_generator = JwtGenerator(key, cert)
            jwt, jwt_auth = jwt_generator.generate_validation_jwt(jwt_data)
            pdf = create_pdf_with_attachment(form.cleaned_data['cda'])
            res = make_validation_request(data, jwt, jwt_auth, pdf)
            response = res
            jwt_data= jwt_generator.verify_token(jwt)
            jwt_auth_data= jwt_generator.verify_token(jwt_auth)
    else:
        #load session data
        session_data={}
        for k in ValidationForm.declared_fields.keys():
            if request.session.get(k,False):
                session_data[k]=request.session[k]
        if session_data:
            form = ValidationForm(initial=session_data)
        else:
            form = ValidationForm()
    return render(request, 'validation.html',
                  context={'form': form, "jwt": jwt,
                           "jwt_auth": jwt_auth,
                           "response": response,
                           'jwt_data': jwt_data,
                           'jwt_auth_data': jwt_auth_data
                           })


def publication(request: HttpRequest):
    jwt = None
    response = None
    jwt_auth = None
    jwt_data = None
    jwt_auth_data = None
    if request.method == 'POST':
        form = PublicationForm(request.POST)
        if form.is_valid():
            for k in form.fields.keys():
                request.session[k]=form.cleaned_data[k]
            jwt_data = JwtData(
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
                person_id=form.cleaned_data['person_id'],
                subject_role=form.cleaned_data['subject_role'],
            )
            # build requestBody from form, also convert every value to string
            data = {
                k:str(form.cleaned_data[k]) for k in form.get_body_parameters() if form.cleaned_data[k]
            }
            pdf = create_pdf_with_attachment(form.cleaned_data['cda'])
            pdf_hash=hashlib.sha256(pdf.getvalue()).hexdigest()
            jwt_data.attachment_hash=pdf_hash
            key = (settings.BASE_DIR/'client_sign').read_bytes()
            cert = (settings.BASE_DIR/'client_sign').read_text()
            certlines = cert.splitlines()
            cert = '\n'.join(
                certlines[certlines.index('-----BEGIN CERTIFICATE-----'):])
            jwt_generator = JwtGenerator(key, cert)
            jwt, jwt_auth = jwt_generator.generate_validation_jwt(jwt_data)
            res = make_publication_request(data, jwt, jwt_auth, pdf)
            response = res
            jwt_data= jwt_generator.verify_token(jwt)
            jwt_auth_data= jwt_generator.verify_token(jwt_auth)
    else:
        session_data={}
        for k in PublicationForm.declared_fields.keys():
            if request.session.get(k,False):
                session_data[k]=request.session[k]
        if session_data:
            form = PublicationForm(initial=session_data)
        else:
            form = PublicationForm()
    return render(request, 'publication.html',
                  context={'form': form, "jwt": jwt,
                           "jwt_auth": jwt_auth,
                           "response": response,
                           'jwt_data': jwt_data,
                           'jwt_auth_data': jwt_auth_data
                           })