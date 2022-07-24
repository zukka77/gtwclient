from jwcrypto import jwk,jwt
import dataclasses
import uuid
import time


@dataclasses.dataclass
class JwtData:
  sub:str
  subject_role:str
  purpose_of_use:str
  iss:str
  locality:str
  subject_organization_id:str
  subject_organization:str
  aud:str
  patient_consent:bool
  action_id:str
  resource_hl7_type:str
  jti=""
  person_id:str
  attachment_hash=""

class JwtGenerator:
  key:bytes
  cert:str
  data:JwtData

  def __init__(self,key:bytes,cert:str,client_name:str="ExampleClient1",exp_time_sec=3600):
    self.key=jwk.JWK.from_pem(key)
    self.exp_time_sec=exp_time_sec
    
    if "BEGIN CERTIFICATE" in cert:
        certpem=list(map(lambda x:x.strip(),cert.splitlines()))
        cert=''.join(certpem[1:-1])
    self.cert=cert
    self.headers={
        "alg": "RS256",
        "typ": "JWT",
        "kid": client_name,
        "x5c": [
          cert
        ]
      }
  
  @staticmethod
  def load_key(path:str)->bytes:
    with open(path,"rb") as f:
        pemkey=f.read()
    return pemkey

  @staticmethod
  def load_crt(path:str)->str:
    with open(path,"r",encoding="utf8") as f:
        certpem=list(map(lambda x:x.strip(),f.readlines()))
        certpem=''.join(certpem[1:-1])
    return certpem

  def generate_validation_jwt(self,data:JwtData):
    nowepoch=int(time.time())
    claims=dataclasses.asdict(data)
    claims.update({
        "iat": nowepoch,
        "nbf": nowepoch,
        "exp": nowepoch+self.exp_time_sec,
        "jti": str(uuid.uuid4()),
      })

    token=jwt.JWT(header=self.headers,claims=claims)
    token.make_signed_token(self.key)
    return token.serialize(compact=True)
