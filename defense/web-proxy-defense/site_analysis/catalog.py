"""One catalog supplies questions, response formats and the axis document."""
import json
from pathlib import Path

STATUSES = ("관찰됨", "없음", "사례 부족", "못 봄")


def load_catalog():
    data = json.loads(Path(__file__).with_name("axes.json").read_text(encoding="utf-8"))
    required(data, "version", "groups", "axes", "call_order")
    for group in data["groups"].values():
        required(group, "name", "merge", "consumers")
        if group["merge"] not in ("union", "consensus", "retain"):
            raise ValueError("등록되지 않은 합치기 규칙")
    if len(set(data["call_order"])) != len(data["call_order"]) or any(group not in data["groups"] for group in data["call_order"]):
        raise ValueError("호출 묶음 목록 오류")
    ids = set()
    for axis in data["axes"]:
        required(axis, "id", "name", "meaning", "question", "group", "consumers")
        if axis["id"] in ids or axis["group"] not in data["groups"]:
            raise ValueError("축 식별자 중복 또는 등록되지 않은 묶음")
        ids.add(axis["id"])
        if axis.get("call_group", axis["group"]) not in data["call_order"]:
            raise ValueError("호출 묶음이 없는 축")
    return data


def required(value, *keys):
    if not isinstance(value, dict) or not set(keys).issubset(value):
        raise ValueError("필수 기록 키 없음: " + ", ".join(keys))


def obj(properties):
    return {"type": "object", "properties": properties,
            "required": list(properties)}


def array(items):
    return {"type": "array", "items": items}


STRING = {"type": "string"}
BOOL = {"type": "boolean"}
ANSWER = obj({"status": {"type": "string", "enum": list(STATUSES)},
              "description": STRING, "evidence": array(STRING),
              "confidence": {"type": ["number", "string", "object", "null"]}})
ANSWER['additionalProperties'] = True
ACTION_SCHEMA = obj({"tool": {"type": "string", "enum": ["open", "click", "inspect_form", "read_sample", "select_page", "stop"]},
                     "args": {"type": "string", "description": "JSON object encoded as a string"},
                     "read_only": BOOL, "human_confirmation": BOOL, "reason": STRING})
ACTION_SCHEMA['properties']['working_notes'] = {
    'type': 'string', 'description': 'Value-free working notes retained for the next navigation decision'}
PRIVACY_SCHEMA = obj({"fields": array(obj({"id": STRING, "safe": BOOL,
                                          "value": STRING}))})
MERGE_ANSWER = obj({"agreement": BOOL, "answer": ANSWER})
ACTION_SCHEMA['properties']['tool']['enum'].append('find')
ANSWER['properties']['final'] = BOOL
PRIVACY_SCHEMA['properties']['fields']['items']['properties']['replacements'] = array(obj({'find': STRING, 'replace': STRING}))
PRIVACY_SCHEMA['properties']['fields']['items']['required'] = ['id', 'safe']


def group_schema(catalog, group):
    return obj({axis["id"]: ANSWER for axis in catalog["axes"]
                if axis.get("call_group", axis["group"]) == group})


def check_answers(catalog, group, response):
    expected = {axis["id"] for axis in catalog["axes"]
                if axis.get("call_group", axis["group"]) == group}
    answers, errors = {}, {}
    for axis_id in expected:
        if isinstance(response, dict) and axis_id in response:
            answers[axis_id] = response[axis_id]
        else:
            errors[axis_id] = 'AxisMissing'
    return answers, errors


def check_answer(answer):
    # Formats are advisory. The model owns its answer and all judgments.
    return answer


def unavailable(reason):
    return {"status": "못 봄", "description": "못 얻음: " + reason, "evidence": [], "confidence": None}


def axis_document(catalog):
    rows = ["# 분석 축", "", "axes.json에서 생성한다. 이 문서를 직접 편집하지 않는다.", "",
            "| 식별자 | 묶음 | 이름 | 뜻 | 질문 | 받는 쪽 |", "| --- | --- | --- | --- | --- | --- |"]
    for axis in catalog["axes"]:
        values = [axis["id"], axis["group"], axis["name"], axis["meaning"],
                  axis["question"], ", ".join(axis["consumers"])]
        rows.append("| " + " | ".join(item.replace("|", "\\|") for item in values) + " |")
    return "\n".join(rows) + "\n"
