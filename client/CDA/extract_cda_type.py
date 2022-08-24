import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TypedDict,List
LOCAL_DIR_PATH=Path(__file__).resolve().parent

class ResultElem(TypedDict):
    file_path:Path
    file_name:str
    code:str
    codeSystem:str
    displayName:str

_CDA_LIST=[]
def get_available_cda()->List[ResultElem]:
    global _CDA_LIST
    if _CDA_LIST:
        return _CDA_LIST
    res=[]
    for p in LOCAL_DIR_PATH.glob('*.xml'):
        cda=ET.parse(p)
        root=cda.getroot()
        code=root.find('./{urn:hl7-org:v3}code[@codeSystem="2.16.840.1.113883.6.1"]')
        result_elem:ResultElem={
            "file_path":str(p.absolute()),
            "file_name":p.name,
            "code":code.get('code'),
            "codeSystem":code.get('codeSystem'),
            "displayName":code.get('displayName')

        }
        res.append(result_elem)
    _CDA_LIST=res
    return res