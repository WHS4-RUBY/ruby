"""Publication and merging operate on our keys and numeric values only."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import tempfile
import time

from .catalog import unavailable

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[2]
PRIVATE = ROOT / ".tmp"


def now():
    return datetime.now(timezone.utc).isoformat()


def ref(value):
    return sha256(value.encode("utf-8")).hexdigest()


def measured(value=None, status="관찰됨", error=None):
    return {"source": "browser", "status": status, "value": value, "error": error}


def isolated(function):
    try:
        return measured(function())
    except Exception as error:
        return {**measured(status="못 얻음", error=type(error).__name__), "_private_detail": str(error)}


async def isolated_async(function):
    try:
        return measured(await function())
    except Exception as error:
        return {**measured(status="못 얻음", error=type(error).__name__), "_private_detail": str(error)}


def private_path(path):
    return Path(path).resolve()


class Failures:
    """Count repetitions of the same operation and failure, never successes."""
    def __init__(self, limit=8):
        self.limit, self.counts, self.stopped = limit, {}, False

    def add(self, operation, reason):
        key = (ref(operation), ref(reason))
        self.counts[key] = self.counts.get(key, 0) + 1
        # Only this operation gives up; unrelated stages keep going (stopped stays False).
        return self.counts[key] >= self.limit

    def clear(self, operation):
        operation = ref(operation)
        self.counts = {key: count for key, count in self.counts.items() if key[0] != operation}

    def exhausted(self, operation):
        return any(key[0] == ref(operation) and count >= self.limit for key, count in self.counts.items())

    def record(self):
        return {"limit": self.limit, "stopped": self.stopped,
                "counts": [{"operation_sha256": key[0], "failure_sha256": key[1], "count": count}
                           for key, count in self.counts.items()]}


def public_facts(value):
    if isinstance(value, dict):
        return {key: public_facts(item) for key, item in value.items() if not key.startswith('_private_')}
    if isinstance(value, list):
        return [public_facts(item) for item in value]
    return value


def json_safe(value):
    if isinstance(value, float) and not math.isfinite(value):
        return {"status": "못 얻음", "value": None, "error": "NonFiniteNumber"}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    return value


def replace_file(source, target):
    """Windows refuses to replace a file another process holds open, such as a reader or scanner."""
    for attempt in range(100):
        try:
            Path(source).replace(target)
            return
        except PermissionError:
            if attempt == 99:
                raise
            time.sleep(0.05 * min(attempt + 1, 10))


def write_json(path, value, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.', suffix='.pending')
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(json_safe(value), stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if private:
            from .resume import owner_only
            owner_only(temporary)
        replace_file(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def merge(catalog, runs, judgments=None):
    modes = {run.get('authority', {}).get('requested', 'anonymous') for run in runs}
    if len(modes) > 1:
        raise ValueError('서로 다른 관찰 권한을 합칠 수 없음')
    judgments = judgments or {}
    axes = {}
    for axis in catalog["axes"]:
        answers = [run["axes"].get(axis["id"], unavailable("축 누락")) for run in runs]
        judgment = judgments.get(axis["id"], {})
        agreement = judgment.get("agreement") if len(answers) > 1 else None
        # The representative answer is the model's combined answer. Code does not pick a run's answer by
        # reading its status word; the group policy only decides whether a disagreeing consensus is withheld.
        mode = catalog["groups"][axis["group"]]["merge"]
        if mode == "consensus":
            chosen = agreement is True
            disposition = "agreed" if chosen else "withheld_no_consensus"
        else:
            chosen = True
            disposition = "union_of_runs" if mode == "union" else "retain_per_run"
        axes[axis["id"]] = {"source": "record_keys", "group": axis["group"], "merge_rule": mode,
                            "agreement": agreement, "disagreement": agreement is False,
                            "disposition": disposition, "run_indices": [runs[i].get('run', i + 1) for i in range(len(answers))],
                            "answers": answers,
                            "combined_answer": judgment.get("answer"),
                            "answer": judgment.get("answer") if chosen else None,
                            "merge_error": judgment.get("error"),
                            "comparison_source": "model" if judgment else "못 얻음"}
    return {"source": "record_keys_and_model", "comparison": "model semantic agreement",
            "axes": axes,
            "agreement_count": sum(axis["agreement"] is True for axis in axes.values()),
            "disagreement_count": sum(axis["disagreement"] for axis in axes.values()),
            "axis_count": len(axes)}


def runs_by_authority(runs):
    groups = {}
    for run in runs:
        mode = run.get('authority', {}).get('requested', 'anonymous')
        groups.setdefault(mode, []).append(run)
    return groups


def merge_by_authority(catalog, runs, judgments=None):
    judgments = judgments or {}
    return {mode: merge(catalog, rows, judgments.get(mode)) if len(rows) > 1 else rows[0]
            for mode, rows in runs_by_authority(runs).items()}


def empty_axes(catalog, reason):
    return {axis["id"]: {**unavailable(reason), "source": "analysis_runner",
                         "requested_source": "model"} for axis in catalog["axes"]}
