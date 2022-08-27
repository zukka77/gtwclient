from django.urls import reverse,reverse_lazy
from client.views import get_issuer,ValidationForm,PublicationForm
from client.xml_initial import cda
from client.datasets import RUOLO_CHOICES,STRUTTURA_CHOICES,TIPO_DOCUMENTO_ALTO_CHOICES,ATTIVITA_CLINICA_CHOICES,ASSETTO_ORGNIZZATIVO_CHOICES
from uuid import uuid4
from datetime import datetime
import pytest
import requests

_POST_RETURN_VALUE_TEXT="""
                        {"traceID": "0634d02b639ac7d0",
                         "spanID": "0634d02b639ac7d0",
                         "workflowInstanceId": "2.16.840.1.113883.2.9.2.120.4.4.97bb3fc5bee3032679f4f07419e04af6375baafa17024527a98ede920c6812ed.6c60c58408^^^^urn:ihe:iti:xdw:2013:workflowInstanceId"
                        }
                     """
_VALIDATION_DATA={
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

_PUBLICATION_DATA={
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

_POST_DATA=[(reverse('client_validation'),ValidationForm,_VALIDATION_DATA,),(reverse('client_publication'),PublicationForm,_PUBLICATION_DATA,)]
_POST_IDS=_GET_IDS=["VALIDATION","PUBLICATION"]

@pytest.mark.parametrize("url",[reverse('client_validation'),reverse('client_publication')],ids=_GET_IDS)
def test_get(url,client):
    response=client.get(url)
    assert response.status_code==200


@pytest.mark.parametrize("url,form_class,data",_POST_DATA,ids=_POST_IDS)
@pytest.mark.django_db
def test_post(mocker,client,url,form_class,data):
    mocker.patch("requests.Session.post")
    type(requests.Session().post().request).headers=mocker.PropertyMock(return_value={}) #NOSONAR
    type(requests.Session().post()).text=mocker.PropertyMock(return_value=_POST_RETURN_VALUE_TEXT) #NOSONAR
    type(requests.Session().post()).status_code=mocker.PropertyMock(return_value=201) #NOSONAR

    form=form_class(data)
    print(form.errors)
    assert form.is_valid()
    
    response=client.post(url,data=data)
    assert response.status_code==200
    #Test invalid form
    data={"test":"test"}
    form=form_class(data)
    assert form.is_valid() == False
    response=client.post((url),data=data)
    
    assert response.status_code==200
    #test session
    client.get(url)
    assert client.session.get("healthDataFormat")=='CDA'


def test_api_examples_cda(client):
        response=client.get(reverse_lazy("api-1.0.0:get_example_cda"))
        assert response.status_code==200
        data=response.json()
        response=client.get(reverse_lazy("api-1.0.0:get_example_cda_id",args=[data[0]['code']]))
        assert response.status_code==200
