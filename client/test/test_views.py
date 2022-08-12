from django.test import Client
from django.urls import reverse
from client.views import get_issuer
from client.xml_initial import cda
from client.datasets import RUOLO_CHOICES,STRUTTURA_CHOICES,TIPO_DOCUMENTO_ALTO_CHOICES,ATTIVITA_CLINICA_CHOICES,ASSETTO_ORGNIZZATIVO_CHOICES
from client.views import ValidationForm,PublicationForm
from uuid import uuid4
from datetime import datetime

def test_validation():
    c=Client()
    response=c.get(reverse('client_validation'))
    assert response.status_code==200

def test_post_validation(mocker):
    m=mocker.patch("requests.Session")
    data={
        "healthDataFormat":"CDA",
        "mode":"ATTACHMENT",
        "activity":"VALIDATION",
        "sub":"PROVAX00X00X000Y",
        "subject_role":RUOLO_CHOICES[0][0],
        "purpose_of_use":"TREATMENT",
        "iss":get_issuer(),
        "locality":"201123456",
        "subject_organization":"Regione Emilia-Romagna",
        "subject_organization_id":"080",
        "aud":"https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1",
        "patient_consent":True,
        "action_id":"CREATE",
        "resource_hl7_type":"('11502-2^^2.16.840.1.113883.6.1')",
        "person_id":"RSSMRA22A01A399Z^^^&amp;2.16.840.1.113883.2.9.4.3.2&amp;ISO",
        "cda":cda,
        }
    form=ValidationForm(data)
    print(form.errors)
    assert form.is_valid()
    c=Client()
    response=c.post(reverse('client_validation'),data=data
    )
    assert response.status_code==200
     #Test invalid form
    data={"test":"test"}
    form=ValidationForm(data)
    assert form.is_valid() == False
    response=c.post(reverse('client_validation'),data=data
    )
    assert response.status_code==200

def test_publication():
    c=Client()
    response=c.get(reverse('client_publication'))
    assert response.status_code==200

def test_post_publication(mocker):
    m=mocker.patch("requests.Session")
    data={
        "healthDataFormat":"CDA",
        "mode":"ATTACHMENT",
        "activity":"VALIDATION",
        "sub":"PROVAX00X00X000Y",
        "subject_role":RUOLO_CHOICES[0][0],
        "purpose_of_use":"TREATMENT",
        "iss":get_issuer(),
        "locality":"201123456",
        "subject_organization":"Regione Emilia-Romagna",
        "subject_organization_id":"080",
        "aud":"https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1",
        "patient_consent":True,
        "action_id":"CREATE",
        "resource_hl7_type":"('11502-2^^2.16.840.1.113883.6.1')",
        "person_id":"RSSMRA22A01A399Z^^^&amp;2.16.840.1.113883.2.9.4.3.2&amp;ISO",
        "cda":cda,
        "workflowInstanceId":"",
        "tipologiaStruttura": STRUTTURA_CHOICES[0][0],
        "attiCliniciRegoleAccesso":[],
        "identificativoDoc":str(uuid4()),
        "identificativoRep":str(uuid4()),
        "tipoDocumentoLivAlto": TIPO_DOCUMENTO_ALTO_CHOICES[0][0],
        "assettoOrganizzativo":ASSETTO_ORGNIZZATIVO_CHOICES[0][0],
        "dataInizioPrestazione":datetime.now(),
        "dataFinePrestazione":datetime.now(),
        "conservazioneANorma":True,
        "tipoAttivitaClinica":ATTIVITA_CLINICA_CHOICES[0][0],
        "identificativoSottomissione":str(uuid4()),
        "priorita":True,
        }
    form=PublicationForm(data)
    print(form.errors)
    assert form.is_valid()
    c=Client()
    response=c.post(reverse('client_publication'),data=data
    )
    assert response.status_code==200
    #Test invalid form
    data={"test":"test"}
    form=PublicationForm(data)
    assert form.is_valid() == False
    response=c.post(reverse('client_publication'),data=data
    )
    assert response.status_code==200