# FSE GTW Web Client
Questo semplice client web, realizzato con [Django](https://www.djangoproject.com/), è utile per sperimentare velocemente le chiamate verso il Gateway FSE 2.0.  
Al momento è possibile effettuare la chiamata di validazione che esegue un controllo formale sul file CDA inviato.  
Il file prima dell'invio viene iniettato all'interno di un pdf di test così come richiesto dalle specifiche.  

## Certificati

Per poter collegarsi alla piattaforma è necessario avere a disposizione la coppia di certificati x509 di autenticazione e di firma.  
I certificati devono essere ognuno in un unico file con la chiave concatenata al certificato in formato pem.

        -----BEGIN PRIVATE KEY-----
        .....
        -----END PRIVATE KEY-----
        -----BEGIN CERTIFICATE-----
        ......
        -----END CERTIFICATE-----


Se si dispone dei file p12 è possibile ottenere le 2 componenti dei certificati mediante il comando openssl:

        openssl pkcs12 -nodes -in nomefile.p12

e specificando la password di importazione.  
*NB* se openssl dovesse dare un errore di formato non compatible sul certificato provare ad aggiungere il parametro `-legacy`

--- 

# ATTENZIONE

**Non esporre pubblicamente il servizio**

---

## Esecuzione

Ci sono 2 modalità di esecuazione del client:
* [come progetto Django sul proprio pc](#esecuzione-locale)
* [come container](#esecuzione-container)

## Esecuzione locale

È necessario python > 3.4 
si consiglia l'utilizzo di un virtual environment

        python -m venv venv
        . venv/bin/activate

- installazione dipendenze:

        pip install -r requirements.txt

- inizializzazione database (la configurazione standatd creerà un database sqlite locale):

        ./management migrate

- certificati:
  - mettere il file `client_auth` contenente i certificati di autenticazione nella directory base (quella contenente **management.py**)
  - mettere il file `client_sign` contenente i certificati di firma nella directory base

a questo punto è sufficiente avviare è possibile avviare il server di sviluppo con:

        ./manage.py runserver

questo farà partire il server di sviluppo sulla porta **8000** ci si potrà quindi collegare a [http://localhost:8000](http://localhost:8000)

Per l'esposizione del servizio verso l'esterno è necessario:

- nel file settings.py
  - Cambiare la variabile `DEBUG` a False
  - Generare una nuova stringa `SECRET_KEY`
    - è possibile farlo con:
  
            python -c "import secrets;print(secrets.token_hex())"


- lanciare il programma con **gunicorn** (già installato tra le dipendenze) dalla directory base

        gunicorn -b 0.0.0.0:4000 -w4  --access-logfile - --error-logfile - -t16 gtwclient.wsgi


## Esecuzione container

Nel source tree è presente il Dockerfile per la generazione di un container.  
È possibile eseguire il build con il comando:

        docker build . -t gtwclient:latest

`gtwclient:latest` è un nome di esempio è possibile scegliere il nome che si preferisce.  
Se si utilizza podman e buildah al posto di docker è possible eseguire il build con:

        buildah bud -t gtwclient:latest

Per l'esecuzione è necessario passare i **certificati** al container, ciò avviene attraverso l'environment di esecuzione nelle variabili `CLIENT_AUTH` e `CLIENT_SIGN`:

        docker run --rm -ti -e CLIENT_AUTH="$(cat client_auth)" -e CLIENT_SIGN="$(cat client_sign)" -p 4000:4000 gtwclient

o in alternativa:

        podman run --rm -ti -e CLIENT_AUTH="$(cat client_auth)" -e CLIENT_SIGN="$(cat client_sign)" -p 4000:4000 gtwclient

dove `client_auth` contiene i certificati di autenticazione, `client_sign` contiene i certificati di firma.  
A questo punto sarà possibile collegarsi al client su [http://localhost:4000](http://localhost:4000)
