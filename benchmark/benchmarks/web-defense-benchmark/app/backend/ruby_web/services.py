from __future__ import annotations

import hashlib
import io
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

from minio import Minio
from redis import Redis


class SessionStore(Protocol):
    def create(self, user_id: str, ttl_seconds: int) -> str: ...
    def resolve(self, token: str) -> str | None: ...
    def delete(self, token: str) -> None: ...
    def delete_user(self, user_id: str) -> None: ...
    def clear(self) -> None: ...
    def session_state_items(self) -> tuple[str, ...]: ...


class ObjectStore(Protocol):
    def ensure_bucket(self) -> None: ...
    def put(self, key: str, content: bytes, content_type: str) -> None: ...
    def exists(self, key: str) -> bool: ...
    def get(self, key: str) -> bytes: ...
    def clear(self) -> None: ...
    def object_state_items(self) -> tuple[str, ...]: ...


class JobQueue(Protocol):
    def enqueue_attachment(self, attachment_id: str) -> None: ...
    def next_attachment(self, timeout_seconds: int) -> str | None: ...
    def clear(self) -> None: ...
    def queue_state_items(self) -> tuple[str, ...]: ...


def _token_key(token: str) -> str:
    return "session:" + hashlib.sha256(token.encode()).hexdigest()


class RedisSessionStore:
    def __init__(self, client: Redis) -> None:
        self.client = client

    def create(self, user_id: str, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        self.client.set(_token_key(token), user_id, ex=ttl_seconds)
        return token

    def resolve(self, token: str) -> str | None:
        value = self.client.get(_token_key(token))
        return value.decode() if isinstance(value, bytes) else value

    def delete(self, token: str) -> None:
        self.client.delete(_token_key(token))

    def delete_user(self, user_id: str) -> None:
        matching = []
        for key in self.client.scan_iter(match="session:*", count=500):
            value = self.client.get(key)
            decoded = value.decode() if isinstance(value, bytes) else value
            if decoded == user_id:
                matching.append(key)
        if matching:
            self.client.unlink(*matching)

    def clear(self) -> None:
        keys = list(self.client.scan_iter(match="session:*", count=500))
        if keys:
            self.client.unlink(*keys)

    def session_state_items(self) -> tuple[str, ...]:
        rows = []
        for key in self.client.scan_iter(match="session:*", count=500):
            value = self.client.get(key)
            key_text = key.decode() if isinstance(key, bytes) else str(key)
            value_text = value.decode() if isinstance(value, bytes) else str(value)
            rows.append(f"{key_text}={value_text}")
        return tuple(sorted(rows))


class RedisJobQueue:
    KEY = "ruby-web:attachment-jobs"

    def __init__(self, client: Redis) -> None:
        self.client = client

    def enqueue_attachment(self, attachment_id: str) -> None:
        self.client.rpush(self.KEY, attachment_id)

    def next_attachment(self, timeout_seconds: int) -> str | None:
        del timeout_seconds
        value = self.client.lpop(self.KEY)
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else value

    def clear(self) -> None:
        self.client.delete(self.KEY)

    def queue_state_items(self) -> tuple[str, ...]:
        values = self.client.lrange(self.KEY, 0, -1)
        return tuple(value.decode() if isinstance(value, bytes) else str(value) for value in values)


class MinioObjectStore:
    def __init__(self, client: Minio, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    def ensure_bucket(self) -> None:
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def put(self, key: str, content: bytes, content_type: str) -> None:
        self.client.put_object(
            self.bucket,
            key,
            io.BytesIO(content),
            len(content),
            content_type=content_type,
        )

    def exists(self, key: str) -> bool:
        self.client.stat_object(self.bucket, key)
        return True

    def get(self, key: str) -> bytes:
        response = self.client.get_object(self.bucket, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def clear(self) -> None:
        for item in self.client.list_objects(self.bucket, recursive=True):
            self.client.remove_object(self.bucket, item.object_name)

    def object_state_items(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                f"{item.object_name}:{item.size}:{item.etag or ''}"
                for item in self.client.list_objects(self.bucket, recursive=True)
            )
        )


@dataclass
class MemoryServices(SessionStore, ObjectStore, JobQueue):
    sessions: dict[str, str] = field(default_factory=dict)
    objects: dict[str, bytes] = field(default_factory=dict)
    jobs: deque[str] = field(default_factory=deque)

    def create(self, user_id: str, ttl_seconds: int) -> str:
        del ttl_seconds
        token = secrets.token_urlsafe(24)
        self.sessions[_token_key(token)] = user_id
        return token

    def resolve(self, token: str) -> str | None:
        return self.sessions.get(_token_key(token))

    def delete(self, token: str) -> None:
        self.sessions.pop(_token_key(token), None)

    def delete_user(self, user_id: str) -> None:
        stale = [key for key, value in self.sessions.items() if value == user_id]
        for key in stale:
            self.sessions.pop(key, None)

    def clear(self) -> None:
        self.sessions.clear()
        self.objects.clear()
        self.jobs.clear()

    def session_state_items(self) -> tuple[str, ...]:
        return tuple(sorted(f"{key}={value}" for key, value in self.sessions.items()))

    def object_state_items(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                f"{key}:{len(value)}:{hashlib.sha256(value).hexdigest()}"
                for key, value in self.objects.items()
            )
        )

    def queue_state_items(self) -> tuple[str, ...]:
        return tuple(self.jobs)

    def ensure_bucket(self) -> None:
        return None

    def put(self, key: str, content: bytes, content_type: str) -> None:
        del content_type
        self.objects[key] = content

    def exists(self, key: str) -> bool:
        return key in self.objects

    def get(self, key: str) -> bytes:
        return self.objects[key]

    def enqueue_attachment(self, attachment_id: str) -> None:
        self.jobs.append(attachment_id)

    def next_attachment(self, timeout_seconds: int) -> str | None:
        del timeout_seconds
        return self.jobs.popleft() if self.jobs else None
