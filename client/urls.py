from django.urls import path
from .views import validation, publication, certificate_view
from .api import api


urlpatterns = [
    path("validation/", validation, name="client_validation"),
    path("publication/", publication, name="client_publication"),
    path("cert/", certificate_view, name="certificate_view"),
    path("api/", api.urls),
]
