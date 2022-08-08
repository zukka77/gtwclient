from django.urls import path
from .views import validation,publication

urlpatterns=[
    path('validation/',validation,name="client_validation"),
    path('publication/',publication,name="client_publication")
]