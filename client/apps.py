from django.apps import AppConfig
#from .models import X509
#import tempfile
#import pathlib
#import os
class ClientConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'client'
    """ def ready(self) -> None:
        try:
            cert=X509.objects.get("auth")
            crt=cert.crt
            key=cert.key
            client_auth='\n'.join([key,crt])
            filepath=pathlib(tempfile.gettempdir)/'client_auth'
            with open(pathlib(tempfile.gettempdir)/'client_auth','w') as f:
                os.chmod(filepath,0o0400)
                f.write(client_auth)
        except:
            pass
        return super().ready()
"""