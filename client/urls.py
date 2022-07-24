from django.urls import path
from .views import *

urlpatterns=[
    path('',index,name="client_index")
]