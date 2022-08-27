from django.urls import path
from .views import validation,publication
from .api import api


urlpatterns=[
    path('validation/',validation,name="client_validation"),
    path('publication/',publication,name="client_publication"),
    path('api/',api.urls),
]