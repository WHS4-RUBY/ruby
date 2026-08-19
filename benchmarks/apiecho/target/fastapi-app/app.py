import asyncio
import json
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request

DATA_DIR = Path("/app/data")
DELIMITER_PATH = "/dev/null"


def emit_delimiter(action: str, request_id: str) -> None:
    payload = f"python {action} {request_id}.\n".encode()
    delimiter_fd = os.open(
        DELIMITER_PATH, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600
    )
    try:
        os.write(delimiter_fd, payload)
    finally:
        os.close(delimiter_fd)


@asynccontextmanager
async def lifespan(_: FastAPI):
    emit_delimiter("request_start", "0")
    yield


app = FastAPI(title="APIEcho target", lifespan=lifespan)


@app.middleware("http")
async def apiecho_request_delimiters(request: Request, call_next):
    request_id = str(uuid4())
    emit_delimiter("request_start", request_id)
    try:
        response = await call_next(request)
        response.headers["X-APIEcho-Request-ID"] = request_id
        return response
    finally:
        emit_delimiter("request_end", request_id)


def load_records(name: str) -> dict[str, dict[str, object]]:
    with (DATA_DIR / name).open(encoding="utf-8") as handle:
        return json.load(handle)


async def run_local_anomaly_behavior(request_id: str) -> None:
    path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="apiecho-anomaly-", suffix=".txt", delete=False
        ) as handle:
            path = handle.name
            handle.write(f"request={request_id}\n")
        Path(path).read_bytes()
        Path("/etc/passwd").read_bytes()

        process = await asyncio.create_subprocess_exec(
            "/bin/sh",
            "-c",
            "printf apiecho-anomaly >/tmp/apiecho-subprocess-output && cat /proc/self/status >/dev/null",
        )
        return_code = await process.wait()
        if return_code != 0:
            raise RuntimeError(f"anomaly subprocess exited with {return_code}")

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", 9), timeout=0.2
            )
        except (ConnectionError, OSError, TimeoutError):
            pass
        else:
            writer.close()
            await writer.wait_closed()
    finally:
        if path is not None:
            Path(path).unlink(missing_ok=True)
        Path("/tmp/apiecho-subprocess-output").unlink(missing_ok=True)


@app.get("/api/users/{record_id}")
async def user(
    record_id: int,
    request: Request,
    experiment: str | None = Query(default=None),
) -> dict[str, object]:
    records = load_records("users.json")
    record = records.get(str(record_id))
    if record is None:
        raise HTTPException(status_code=404, detail="user not found")
    if experiment == "anomaly":
        await run_local_anomaly_behavior(
            request.headers.get("X-Request-ID", str(uuid4()))
        )
    return record


@app.get("/api/products/{record_id}")
async def product(record_id: int) -> dict[str, object]:
    records = load_records("products.json")
    record = records.get(str(record_id))
    if record is None:
        raise HTTPException(status_code=404, detail="product not found")
    return record
