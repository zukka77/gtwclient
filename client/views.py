from datetime import datetime
from io import BytesIO
from requests.exceptions import SSLError
from uuid import uuid4
from django.shortcuts import render
from django import forms
from django.http import HttpRequest
from .FSEgtwUtils import create_pdf_with_attachment, sign_pdf, JwtGenerator, JwtData
from django.conf import settings
from typing import Iterable, List, Optional
import requests
import json
from .xml_initial import cda
from .datasets import (
    ASSETTO_ORGNIZZATIVO_CHOICES,
    ATTIVITA_CLINICA_CHOICES,
    RESOURCE_HL7_TYPE_CHOICES,
    REGOLE_DI_ACCESSO_CHOICES,
    RUOLO_CHOICES,
    STRUTTURA_CHOICES,
    TIPO_DOCUMENTO_ALTO_CHOICES,
)
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
import functools
import hashlib
from enum import Enum, auto


class CertificateErrorException(Exception):
    pass


class CertificateNotFoundException(CertificateErrorException):
    pass


class CertificateNotValidException(CertificateErrorException):
    pass


class CertType(Enum):
    AUTH = auto()
    SIGN = auto()


def get_certs_path(cert: CertType) -> List[Path]:
    paths = []
    if cert == CertType.SIGN:
        for f in ("client_sign_upload", "client_sign"):
            if (settings.BASE_DIR / f).exists():
                paths.append(settings.BASE_DIR / f)
        return paths
    if cert == CertType.AUTH:
        for f in ("client_auth_upload", "client_auth"):
            if (settings.BASE_DIR / f).exists():
                paths.append(settings.BASE_DIR / f)
        return paths
    raise ValueError(f"{cert} is not a valid CertType")


def get_cert_cn(cert_path: Optional[Path] = None) -> str:
    if cert_path:
        cert_paths = [cert_path]
    else:
        cert_paths = get_certs_path(CertType.SIGN)
    for cert_path in cert_paths:
        try:
            crt = x509.load_pem_x509_certificate(cert_path.read_bytes())
            iss = crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            return str(iss)
        except:  # nosec
            pass
    if not cert_paths:
        raise CertificateNotFoundException("Certificate not found")
    raise CertificateNotValidException(f"certs: {cert_paths} is/are not valid")


def split_key_cert(file_path: Path) -> tuple[bytes, str]:
    key = file_path.read_bytes()
    cert = file_path.read_text()
    certlines = cert.splitlines()
    cert = "\n".join(certlines[certlines.index("-----BEGIN CERTIFICATE-----") :])
    return (key, cert)


def build_jwt_generator() -> JwtGenerator:
    file_paths = get_certs_path(CertType.SIGN)
    for file_path in file_paths:
        try:
            key, cert = split_key_cert(file_path)
            return JwtGenerator(key, cert)
        except:  # nosec
            pass
    if not file_paths:
        raise CertificateNotFoundException("Certificate not found")
    raise CertificateNotValidException(f"certs: {file_paths} is/are not valid")


def use_jwt_generator(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        jwt_generator = build_jwt_generator()
        return func(jwt_generator, *args, **kwargs)

    return wrapper


class CertForm(forms.Form):
    client_auth = forms.CharField(
        widget=forms.Textarea(attrs={"cols": "80", "rows": "5"}), required=False, label="certificato di autenticazione"
    )
    client_sign = forms.CharField(
        widget=forms.Textarea(attrs={"cols": "80", "rows": "5"}), required=False, label="certificato di signature"
    )


class WiiForm(forms.Form):
    wii = forms.CharField(required=True, label="workflowInstanceId")


class ValidationForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["iss"].widget.attrs["readonly"] = True
        self.fields["iss"].initial = get_cert_cn()

    # PARAMETRY BODY
    healthDataFormat = forms.ChoiceField(choices=[("CDA", "CDA")])
    mode = forms.ChoiceField(choices=[("ATTACHMENT", "ATTACHMENT")])
    activity = forms.ChoiceField(choices=[("VALIDATION", "VALIDATION")])
    # PARAMETRI JWT
    sub = forms.CharField(initial="PROVAX00X00X000Y^^^&2.16.840.1.113883.2.9.4.3.2&ISO")
    subject_role = forms.ChoiceField(choices=RUOLO_CHOICES)
    purpose_of_use = forms.ChoiceField(choices=[("TREATMENT", "TREATMENT")])
    iss = forms.CharField()
    locality = forms.CharField(initial="201123456")
    subject_organization = forms.CharField(initial="Regione Emilia-Romagna")
    subject_organization_id = forms.CharField(initial="080")
    aud = forms.CharField(initial="https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1", disabled=True)
    patient_consent = forms.BooleanField(initial=True, disabled=True)
    action_id = forms.ChoiceField(choices=[("CREATE", "CREATE")])
    # resource_hl7_type = forms.CharField(
    #    initial="('11502-2^^2.16.840.1.113883.6.1')")
    resource_hl7_type = forms.ChoiceField(
        initial="('11502-2^^2.16.840.1.113883.6.1')", choices=RESOURCE_HL7_TYPE_CHOICES
    )
    person_id = forms.CharField(initial="GTWGWY82B42G920M^^^&2.16.840.1.113883.2.9.4.3.2&ISO")
    cda = forms.CharField(widget=forms.Textarea(attrs={"cols": "120", "rows": "30"}), initial=cda)


class PublicationForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["iss"].widget.attrs["readonly"] = True
        self.fields["iss"].initial = get_cert_cn()

    # Validazione contestuale alla pubblicazione
    validateAndPublish = forms.BooleanField(required=False, initial=False, label="Validazione contestuale")
    # PARAMETRY BODY
    workflowInstanceId = forms.CharField(required=False)
    healthDataFormat = forms.ChoiceField(choices=[("CDA", "CDA")])
    mode = forms.ChoiceField(choices=[("ATTACHMENT", "ATTACHMENT")])
    tipologiaStruttura = forms.ChoiceField(choices=STRUTTURA_CHOICES)
    attiCliniciRegoleAccesso = forms.MultipleChoiceField(choices=REGOLE_DI_ACCESSO_CHOICES, required=False)
    identificativoDoc = forms.CharField(initial=str(uuid4()))
    identificativoRep = forms.CharField(initial=str(uuid4()))
    tipoDocumentoLivAlto = forms.ChoiceField(choices=TIPO_DOCUMENTO_ALTO_CHOICES)
    assettoOrganizzativo = forms.ChoiceField(choices=ASSETTO_ORGNIZZATIVO_CHOICES)
    dataInizioPrestazione = forms.DateTimeField(initial=datetime.now, required=False)
    dataFinePrestazione = forms.DateTimeField(initial=datetime.now, required=False)
    conservazioneANorma = forms.BooleanField(initial=False, required=False)
    tipoAttivitaClinica = forms.ChoiceField(choices=ATTIVITA_CLINICA_CHOICES)
    identificativoSottomissione = forms.CharField(initial=str(uuid4()))
    priorita = forms.BooleanField(required=False)
    # PARAMETRI JWT
    sub = forms.CharField(initial="PROVAX00X00X000Y^^^&2.16.840.1.113883.2.9.4.3.2&ISO")
    subject_role = forms.ChoiceField(choices=RUOLO_CHOICES)
    subject_organization = forms.CharField(initial="Regione Emilia-Romagna")
    subject_organization_id = forms.CharField(initial="080")
    purpose_of_use = forms.ChoiceField(choices=[("TREATMENT", "TREATMENT")])
    iss = forms.CharField()
    locality = forms.CharField(initial="201123456")
    aud = forms.CharField(initial="https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1", disabled=True)
    patient_consent = forms.BooleanField(initial=True, disabled=True)
    action_id = forms.ChoiceField(choices=[("CREATE", "CREATE")])
    # resource_hl7_type = forms.CharField(
    #    initial="('11502-2^^2.16.840.1.113883.6.1')")
    resource_hl7_type = forms.ChoiceField(
        initial="('11502-2^^2.16.840.1.113883.6.1')", choices=RESOURCE_HL7_TYPE_CHOICES
    )
    person_id = forms.CharField(initial="RSSMRA22A01A399Z^^^&2.16.840.1.113883.2.9.4.3.2&ISO")
    # REFERTO CDA
    cda = forms.CharField(widget=forms.Textarea(attrs={"cols": "120", "rows": "30"}), initial=cda)

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


def make_validation_request(data: dict, jwt: str, jwt_auth: str, pdf: BytesIO) -> requests.Response:
    VALIDATION_URL = settings.GTW_BASE_URL + "/v1/documents/validation"
    return make_request(VALIDATION_URL, data, jwt, jwt_auth, pdf)


def make_publication_request(data: dict, jwt: str, jwt_auth: str, pdf: BytesIO) -> requests.Response:
    PUBLICATION_URL = settings.GTW_BASE_URL + "/v1/documents"
    return make_request(PUBLICATION_URL, data, jwt, jwt_auth, pdf)


def make_validate_and_publish_request(data: dict, jwt: str, jwt_auth: str, pdf: BytesIO) -> requests.Response:
    VALIDATE_AND_PUBLISH_URL = settings.GTW_BASE_URL + "/v1/documents/validate-and-create"
    return make_request(VALIDATE_AND_PUBLISH_URL, data, jwt, jwt_auth, pdf)


def make_status_request(wii: str, jwt_auth) -> requests.Response:
    STATUS_URL = settings.GTW_BASE_URL + f"/v1/status/{wii}"
    s = requests.Session()
    cert_paths = get_certs_path(CertType.AUTH)
    if not cert_paths:
        raise CertificateNotFoundException
    s.cert = str(cert_paths[0].resolve())
    s.headers.update({"Accept": "application/json"})
    headers = {"Authorization": "Bearer " + jwt_auth}
    http_request = requests.Request(
        "GET",
        STATUS_URL,
        headers=headers,
    )
    http_request = s.prepare_request(http_request)
    res = s.send(http_request)
    return res


def make_request(url: str, data: dict, jwt: str, jwt_auth: str, pdf: BytesIO) -> requests.Response:
    s = requests.Session()
    cert_paths = get_certs_path(CertType.AUTH)
    if not cert_paths:
        raise CertificateNotFoundException
    s.cert = str(cert_paths[0].resolve())
    s.headers.update({"Accept": "application/json"})
    headers = {"Authorization": "Bearer " + jwt_auth, "FSE-JWT-Signature": jwt}
    http_request = requests.Request(
        "POST",
        url,
        headers=headers,
        files=[("file", ("cda.pdf", pdf, "application/pdf"))],
        data=[("requestBody", json.dumps(data))],
    )
    http_request = s.prepare_request(http_request)
    if settings.GTW_DUMP_REQUEST:
        # dump request and pdf used sent to the gtw
        with open("last_request.txt", "w", encoding="utf-8") as f:
            f.write(
                "{}\n{}\r\n{}\r\n\r\n{}".format(
                    "-----------START-----------",
                    str(http_request.method) + " " + str(http_request.url),
                    "\r\n".join("{}: {}".format(k, v) for k, v in http_request.headers.items()),
                    http_request.body,
                )
            )
        with open("last_pdf.pdf", "wb") as f:
            pdf.seek(0)
            f.write(pdf.read())
            pdf.seek(0)
    res = s.send(http_request)

    return res


def build_jwt_data(form: forms.Form) -> JwtData:
    return JwtData(
        action_id=form.cleaned_data["action_id"],
        aud=form.cleaned_data["aud"],
        iss=form.cleaned_data["iss"],
        locality=form.cleaned_data["locality"],
        patient_consent=form.cleaned_data["patient_consent"],
        purpose_of_use=form.cleaned_data["purpose_of_use"],
        resource_hl7_type=form.cleaned_data["resource_hl7_type"],
        sub=form.cleaned_data["sub"],
        subject_organization=form.cleaned_data["subject_organization"],
        subject_organization_id=form.cleaned_data["subject_organization_id"],
        subject_role=form.cleaned_data["subject_role"],
        person_id=form.cleaned_data["person_id"],
    )


def save_data_in_session(request: HttpRequest, form: forms.Form):
    for k in form.fields.keys():
        request.session[k] = (
            str(form.cleaned_data[k]) if type(form.cleaned_data[k]) == datetime else form.cleaned_data[k]
        )


def load_session_data(request: HttpRequest, keys: Iterable[str]) -> dict:
    session_data = {}
    for k in keys:
        if request.session.get(k, False):
            session_data[k] = request.session[k]
    return session_data


###views
@use_jwt_generator
def validation(jwt_generator: JwtGenerator, request: HttpRequest):
    jwt = None
    response = None
    jwt_auth = None
    jwt_data = None
    jwt_auth_data = None
    request_data = None
    if request.GET.get("clear_session") or request.POST.get("clear_session"):
        request.session.flush()
    if request.method == "POST":
        form = ValidationForm(request.POST)
        if form.is_valid():
            # save data in session
            save_data_in_session(request, form)
            jwt_data = build_jwt_data(form=form)
            data = {
                "activity": form.cleaned_data["activity"],
                "mode": form.cleaned_data["mode"],
                "healthDataFormat": form.cleaned_data["healthDataFormat"],
            }
            jwt, jwt_auth = jwt_generator.generate_validation_jwt(jwt_data)
            pdf = create_pdf_with_attachment(form.cleaned_data["cda"])
            request_data = data
            try:
                res = make_validation_request(data, jwt, jwt_auth, pdf)
                response = {
                    "request_headers": dict(res.request.headers),
                    "status_code": res.status_code,
                    "text": res.text,
                }
                wii = None
                try:
                    res_data = res.json()
                    wii = res_data.get("workflowInstanceId")
                except:
                    pass
                if wii:
                    request.session["last_wii"] = wii
            except SSLError:
                response = {
                    "request_headers": {},
                    "status_code": 400,
                    "text": "Errore SSL controllare che si stia usando il certificato giusto.",
                }
            jwt_data = jwt_generator.verify_token(jwt)
            jwt_auth_data = jwt_generator.verify_token(jwt_auth)

    else:
        # load session data
        session_data = load_session_data(request, ValidationForm.declared_fields.keys())
        if session_data and not request.GET.get("no_cache"):
            session_data["iss"] = get_cert_cn()
            form = ValidationForm(initial=session_data)
        else:
            form = ValidationForm(initial={"iss": get_cert_cn()})
    return render(
        request,
        "validation.html",
        context={
            "form": form,
            "jwt": jwt,
            "jwt_auth": jwt_auth,
            "response": response,
            "jwt_data": jwt_data,
            "jwt_auth_data": jwt_auth_data,
            "request_data": request_data,
            "BASE_URL": settings.GTW_BASE_URL,
        },
    )


@use_jwt_generator
def publication(jwt_generator: JwtGenerator, request: HttpRequest):
    jwt = None
    response = None
    jwt_auth = None
    jwt_data = None
    jwt_auth_data = None
    request_data = None
    if request.GET.get("clear_session") or request.POST.get("clear_session"):
        request.session.flush()
    if request.method == "POST":
        form = PublicationForm(request.POST)
        if form.is_valid():
            for k in form.fields.keys():
                request.session[k] = (
                    str(form.cleaned_data[k]) if type(form.cleaned_data[k]) == datetime else form.cleaned_data[k]
                )
            jwt_data = build_jwt_data(form=form)
            # build requestBody from form, also convert every value to string
            data = {
                k: str(form.cleaned_data[k])
                if type(form.cleaned_data[k]) not in (str, int, list)
                else form.cleaned_data[k]
                for k in form.get_body_parameters()
                if form.cleaned_data[k]
            }
            pdf = create_pdf_with_attachment(form.cleaned_data["cda"])
            # sign pdf
            paths = get_certs_path(CertType.SIGN)
            (key, cert) = split_key_cert(paths[0])
            pdf_signed = sign_pdf(cert, key.decode("utf-8"), pdf)
            pdf = pdf_signed
            pdf_hash = hashlib.sha256(pdf.getvalue()).hexdigest()
            jwt_data.attachment_hash = pdf_hash
            jwt, jwt_auth = jwt_generator.generate_validation_jwt(jwt_data)
            request_data = data
            try:
                if form.cleaned_data["validateAndPublish"]:
                    res = make_validate_and_publish_request(data, jwt, jwt_auth, pdf)
                else:
                    res = make_publication_request(data, jwt, jwt_auth, pdf)
                response = {
                    "request_headers": dict(res.request.headers),
                    "status_code": res.status_code,
                    "text": res.text,
                }
                wii = None
                try:
                    res_data = res.json()
                    wii = res_data.get("workflowInstanceId")
                except:
                    pass
                if wii:
                    request.session["last_wii"] = wii
            except SSLError:
                response = {
                    "request_headers": {},
                    "status_code": 400,
                    "text": "Errore SSL controllare che si stia usando il certificato giusto.",
                }
            jwt_data = jwt_generator.verify_token(jwt)
            jwt_auth_data = jwt_generator.verify_token(jwt_auth)
    else:
        session_data = load_session_data(request, PublicationForm.declared_fields.keys())
        if session_data:
            session_data["iss"] = get_cert_cn()
            form = PublicationForm(initial=session_data)
        else:
            form = PublicationForm(initial={"iss": get_cert_cn()})
    return render(
        request,
        "publication.html",
        context={
            "form": form,
            "jwt": jwt,
            "jwt_auth": jwt_auth,
            "response": response,
            "jwt_data": jwt_data,
            "jwt_auth_data": jwt_auth_data,
            "request_data": request_data,
            "BASE_URL": settings.GTW_BASE_URL,
        },
    )


def certificate_view(request: HttpRequest):
    form = None
    auth_cn = None
    sign_cn = None
    if request.method == "POST":
        form = CertForm(request.POST)
        if form.is_valid():
            client_auth = form.cleaned_data["client_auth"]
            client_sign = form.cleaned_data["client_sign"]
            (settings.BASE_DIR / "client_sign_upload").write_text(client_sign, encoding="utf8")
            (settings.BASE_DIR / "client_auth_upload").write_text(client_auth, encoding="utf8")
            try:
                # check if certs are good
                sign_cn = get_cert_cn(settings.BASE_DIR / "client_sign_upload")
                auth_cn = get_cert_cn(settings.BASE_DIR / "client_auth_upload")
            except:
                # delete them if are not...
                (settings.BASE_DIR / "client_sign_upload").unlink()
                (settings.BASE_DIR / "client_auth_upload").unlink()

    if (
        not form
        and (settings.BASE_DIR / "client_sign_upload").exists()
        and (settings.BASE_DIR / "client_auth_upload").exists()
    ):
        form = CertForm(
            initial={
                "client_sign": (settings.BASE_DIR / "client_sign_upload").read_text(encoding="utf8"),
                "client_auth": (settings.BASE_DIR / "client_auth_upload").read_text(encoding="utf8"),
            }
        )
        sign_cn = get_cert_cn(settings.BASE_DIR / "client_sign_upload")
        auth_cn = get_cert_cn(settings.BASE_DIR / "client_auth_upload")
    elif not form:
        form = CertForm()
    return render(
        request,
        "cert_upload.html",
        context={"auth_cn": auth_cn, "sign_cn": sign_cn, "form": form, "BASE_URL": settings.GTW_BASE_URL},
    )


@use_jwt_generator
def wii_status_view(jwt_generator: JwtGenerator, request: HttpRequest):
    wii = request.session.get("last_wii", None)
    status_data = None
    status_code = None
    if request.method == "POST":
        wii_form = WiiForm(request.POST)
        if wii_form.is_valid():
            jwt = jwt_generator.generate_auth_jwt(
                sub="BAO", iss=get_cert_cn(), aud="https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1"
            )
            res = make_status_request(wii_form.cleaned_data["wii"], jwt)
            status_code = res.status_code
            status_data = res.text
    else:
        if wii:
            wii_form = WiiForm(initial={"wii": wii})
        else:
            wii_form = WiiForm()
    return render(
        request,
        "wii_status.html",
        context={
            "status_code": status_code,
            "status_data": status_data,
            "BASE_URL": settings.GTW_BASE_URL,
            "form": wii_form,
        },
    )
