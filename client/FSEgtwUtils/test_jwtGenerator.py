from .jwtGenerator import JwtGenerator,JwtData
from jwcrypto import jwk
from pytest import fixture
from typing import NamedTuple

class Keys(NamedTuple):
    priv:bytes
    pub:bytes

@fixture(scope="session")
def test_keys()->Keys:
    key=jwk.JWK.generate(kty="RSA",size=2048)
    pem_priv_key=key.export_to_pem(private_key=True,password=None)
    pem_pub_key=key.export_to_pem(private_key=False,password=None)
    
    return Keys(priv=pem_priv_key,pub=pem_pub_key)

def test_jwt_generator(test_keys:Keys):
    jwt_generator=JwtGenerator(key=test_keys.priv,cert=test_keys.pub.decode('utf8'))
    data=JwtData(action_id="action_id",
                 attachment_hash="attachment_hash",
                 aud="aud",
                 iss="iss",
                 jti="jti",
                 locality="locality",
                 patient_consent=True,
                person_id="person_id",
                purpose_of_use="pou",
                resource_hl7_type="rhl7t",
                sub="sub",
                subject_organization="s_org",
                subject_organization_id="s_org_id",
                subject_role="s_role"
                )
    jwt=jwt_generator.generate_validation_jwt(data)
    print (f"{jwt[1]}")

    assert jwt[0]
    assert jwt[1]
    data=jwt_generator.verify_token(jwt[0])
    assert data['header']
    assert data['payload']
    data=jwt_generator.verify_token(jwt[1])
    assert data['header']
    assert data['payload']
    print (f"{jwt[1]}")
