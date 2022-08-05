from django.urls import path
from .views import validation

urlpatterns=[
    path('validation/',validation,name="client_validation")
]