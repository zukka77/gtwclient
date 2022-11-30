from ninja import NinjaAPI
from .FSEgtwUtils import get_available_cda
from pathlib import Path

api = NinjaAPI()


@api.get("/example-cda")
def get_example_cda(request) -> list[dict]:
    available_cda = get_available_cda()
    # filter only public data
    available_cda = list(
        map(lambda x: {k: v for k, v in x.items() if k in ["code", "displayName", "codeSystem"]}, available_cda)
    )
    return available_cda


@api.get("/example-cda/{code}")
def get_example_cda_id(request, code) -> str:
    available_cda = get_available_cda()
    cda = list(filter(lambda x: x["code"] == code, available_cda))
    cda_path = Path(cda[0]["file_path"])
    return cda_path.read_text(encoding="utf8")
