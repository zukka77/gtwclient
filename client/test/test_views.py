from client.views import *
from django.test import Client
from django.urls import reverse

def test_validation():
    c=Client()
    response=c.get(reverse('client_validation'))
    assert response.status_code==200

def test_publication():
    c=Client()
    response=c.get(reverse('client_publication'))
    assert response.status_code==200