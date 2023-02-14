import os
from django.urls import reverse, reverse_lazy
from client.views import (
    get_cert_cn,
    ValidationForm,
    PublicationForm,
    WiiForm,
    get_certs_path,
    CertificateNotFoundException,
    CertificateNotValidException,
    build_jwt_generator,
    make_request,
)
from client.xml_initial import cda
from client.datasets import (
    RUOLO_CHOICES,
    STRUTTURA_CHOICES,
    TIPO_DOCUMENTO_ALTO_CHOICES,
    ATTIVITA_CLINICA_CHOICES,
    ASSETTO_ORGNIZZATIVO_CHOICES,
)
from django.conf import settings
from uuid import uuid4
from datetime import datetime
from pathlib import Path
import pytest
import requests
from django.test import Client

_POST_RETURN_VALUE_TEXT = """
                        {"traceID": "0634d02b639ac7d0",
                         "spanID": "0634d02b639ac7d0",
                         "workflowInstanceId": "2.16.840.1.113883.2.9.2.120.4.4.97bb3fc5bee3032679f4f07419e04af6375baafa17024527a98ede920c6812ed.6c60c58408^^^^urn:ihe:iti:xdw:2013:workflowInstanceId"
                        }
                     """
_VALIDATION_DATA = {
    "healthDataFormat": "CDA",
    "mode": "ATTACHMENT",
    "activity": "VALIDATION",
    "sub": "PROVAX00X00X000Y",
    "subject_role": RUOLO_CHOICES[0][0],
    "purpose_of_use": "TREATMENT",
    "iss": get_cert_cn(),
    "locality": "201123456",
    "subject_organization": "Regione Emilia-Romagna",
    "subject_organization_id": "080",
    "aud": "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1",
    "patient_consent": True,
    "action_id": "CREATE",
    "resource_hl7_type": "('11502-2^^2.16.840.1.113883.6.1')",
    "person_id": "RSSMRA22A01A399Z^^^&amp;2.16.840.1.113883.2.9.4.3.2&amp;ISO",
    "cda": cda,
}

_PUBLICATION_DATA = {
    "healthDataFormat": "CDA",
    "mode": "ATTACHMENT",
    "activity": "VALIDATION",
    "sub": "PROVAX00X00X000Y",
    "subject_role": RUOLO_CHOICES[0][0],
    "purpose_of_use": "TREATMENT",
    "iss": get_cert_cn(),
    "locality": "201123456",
    "subject_organization": "Regione Emilia-Romagna",
    "subject_organization_id": "080",
    "aud": "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1",
    "patient_consent": True,
    "action_id": "CREATE",
    "resource_hl7_type": "('11502-2^^2.16.840.1.113883.6.1')",
    "person_id": "RSSMRA22A01A399Z^^^&amp;2.16.840.1.113883.2.9.4.3.2&amp;ISO",
    "cda": cda,
    "workflowInstanceId": "",
    "tipologiaStruttura": STRUTTURA_CHOICES[0][0],
    "attiCliniciRegoleAccesso": [],
    "identificativoDoc": str(uuid4()),
    "identificativoRep": str(uuid4()),
    "tipoDocumentoLivAlto": TIPO_DOCUMENTO_ALTO_CHOICES[0][0],
    "assettoOrganizzativo": ASSETTO_ORGNIZZATIVO_CHOICES[0][0],
    "dataInizioPrestazione": datetime.now(),
    "dataFinePrestazione": datetime.now(),
    "conservazioneANorma": True,
    "tipoAttivitaClinica": ATTIVITA_CLINICA_CHOICES[0][0],
    "identificativoSottomissione": str(uuid4()),
    "priorita": True,
}

_POST_DATA = [
    (
        reverse("client_validation"),
        ValidationForm,
        _VALIDATION_DATA,
    ),
    (
        reverse("client_publication"),
        PublicationForm,
        _PUBLICATION_DATA,
    ),
]
_POST_IDS = _GET_IDS = ["VALIDATION", "PUBLICATION"]


@pytest.mark.parametrize("url", [reverse("client_validation"), reverse("client_publication")], ids=_GET_IDS)
def test_get(url, client):
    response = client.get(url)
    assert response.status_code == 200
    response = client.get(url, {"clear_session": 1})
    assert response.status_code == 200


@pytest.mark.parametrize("url,form_class,data", _POST_DATA, ids=_POST_IDS)
@pytest.mark.django_db
def test_post(mocker, client, url, form_class, data):
    mocker.patch("requests.Session.post")
    type(requests.Session().post().request).headers = mocker.PropertyMock(return_value={})  # NOSONAR
    type(requests.Session().post()).text = mocker.PropertyMock(return_value=_POST_RETURN_VALUE_TEXT)  # NOSONAR
    type(requests.Session().post()).status_code = mocker.PropertyMock(return_value=201)  # NOSONAR

    form = form_class(data)
    print(form.errors)
    assert form.is_valid()

    response = client.post(url, data=data)
    assert response.status_code == 200
    # Test invalid form
    data = {"test": "test"}
    form = form_class(data)
    assert form.is_valid() == False
    response = client.post((url), data=data)

    assert response.status_code == 200
    # test session
    client.get(url)
    assert client.session.get("healthDataFormat") == "CDA"


def test_api_examples_cda(client):
    response = client.get(reverse_lazy("api-1.0.0:get_example_cda"))
    assert response.status_code == 200
    data = response.json()
    for d in data:
        response = client.get(reverse_lazy("api-1.0.0:get_example_cda_id", args=[d["code"]]))
        assert response.status_code == 200


# REALLY UGLY is it possible to call a test within another test?
@pytest.mark.order(-1)
@pytest.mark.parametrize("url,form_class,data", _POST_DATA, ids=_POST_IDS)
@pytest.mark.django_db
def test_cert_upload(mocker, client, url, form_class, data):
    client_sign_path: Path = settings.BASE_DIR / "client_sign"
    client_auth_path: Path = settings.BASE_DIR / "client_auth"
    client_sign_upload_path: Path = settings.BASE_DIR / "client_sign_upload"
    client_auth_upload_path: Path = settings.BASE_DIR / "client_auth_upload"
    if client_sign_upload_path.exists():
        client_sign_upload_path.unlink()
    if client_auth_upload_path.exists():
        client_auth_upload_path.unlink()
    response = client.get(reverse("certificate_view"))
    assert response.status_code == 200
    client.post(reverse("certificate_view"), {"client_auth": "test", "client_sign": "test"})
    assert response.status_code == 200
    assert not client_sign_upload_path.exists()
    assert not client_auth_upload_path.exists()
    test_post(mocker, client, url, form_class, data)
    client.post(
        reverse("certificate_view"),
        {
            "client_auth": client_auth_path.read_text(encoding="utf8"),
            "client_sign": client_sign_path.read_text(encoding="utf8"),
        },
    )
    assert client_sign_upload_path.exists()
    assert client_auth_upload_path.exists()
    test_post(mocker, client, url, form_class, data)
    client.get(reverse("certificate_view"))


def test_get_certs_path_not_valid_cert_type():
    with pytest.raises(ValueError):
        get_certs_path("test")


def test_cert_not_valid_exceptions(mocker):
    with pytest.raises(CertificateNotValidException):
        get_cert_cn(Path(str(uuid4())))
    mocker.patch("client.views.get_certs_path").return_value = [Path(str(uuid4()))]
    with pytest.raises(CertificateNotValidException):
        build_jwt_generator()


def test_cert_not_found_exceptions(mocker):
    mocker.patch("client.views.get_certs_path").return_value = []
    with pytest.raises(CertificateNotFoundException):
        build_jwt_generator()
    with pytest.raises(CertificateNotFoundException):
        get_cert_cn()
    with pytest.raises(CertificateNotFoundException):
        make_request(data=None, jwt_auth=None, jwt=None, pdf=None, url=None)


@pytest.mark.parametrize("url,form_class,data", _POST_DATA, ids=_POST_IDS)
@pytest.mark.django_db
def test_ssl_error(mocker, client, url, data, form_class):
    from requests.exceptions import SSLError

    mocker.patch("client.views.make_request").side_effect = SSLError
    response = client.post(url, data=data)
    assert response.context["response"]["status_code"] == 400


@pytest.mark.django_db
def test_status_view(mocker, client: Client):
    mocker.patch("requests.Session")
    type(requests.Session().send().request).headers = mocker.PropertyMock(return_value={})  # NOSONAR
    type(requests.Session().send()).text = mocker.PropertyMock(return_value="")  # NOSONAR
    type(requests.Session().send()).status_code = mocker.PropertyMock(return_value=201)  # NOSONAR
    data = {"wii": "wii"}
    res = client.get(reverse("wii_status_view"))
    assert res.status_code == 200
    form = WiiForm(data)
    assert form.is_valid()
    res = client.post(reverse("wii_status_view"), data=data)
    assert res.status_code == 200
    session = client.session
    session["last_wii"] = "last_wii"
    session.save()
    res = client.get(reverse("wii_status_view"))
    assert res.status_code == 200
    assert res.context["form"]["wii"].value() == "last_wii"


@pytest.mark.django_db
@pytest.mark.skipif(not os.environ.get("ONLINE_TEST"), reason="ONLINE_TEST env is not set")
def test_status(mocker, client: Client):  # pragma: no cover
    form_class = ValidationForm
    data = _VALIDATION_DATA
    url = reverse("client_validation")
    form = form_class(data)
    print(form.errors)
    assert form.is_valid()

    response = client.post(url, data=data)
    assert response.status_code == 200

    import re

    wii_pattern = re.compile(r"[a-f\.0-9]*\^\^\^\^urn:ihe:iti:xdw:2013:workflowInstanceId")
    bearer_pattern = re.compile(r'"Authorization": "Bearer\s+([^"]*)')
    fjs_pattern = re.compile(r'"FSE-JWT-Signature": "([^"]*)')
    m = wii_pattern.search(response.content.decode("utf8"))
    assert m != None
    wii = m.group(0)
    assert wii != None
    print(f"WII: {wii}")
    m = bearer_pattern.search(response.content.decode("utf8"))
    assert m != None
    bearer = m.group(1)
    m = fjs_pattern.search(response.content.decode("utf8"))
    assert m != None
    fjs = m.group(1)
    assert fjs != None
    from client.views import CertType

    cert_paths = get_certs_path(CertType.AUTH)
    res = requests.get(
        settings.GTW_BASE_URL + f"/v1/status/{wii}",
        headers={"accept": "application/json", "authorization": f"bearer {bearer}", "FSE-JWT-Signature": fjs},
        cert=str(cert_paths[0].resolve()),
    )
    response = res.json()
    print(res.request.url)
    print(response)
    assert res.status_code == 200
