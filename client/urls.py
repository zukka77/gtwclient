from django.urls import path
from .views import *

urlpatterns=[
    path('validation/',validation,name="client_validation")
]