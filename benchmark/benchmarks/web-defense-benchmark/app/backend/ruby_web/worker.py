from __future__ import annotations

import logging
import time

from minio import Minio
from redis import Redis

from .config import Settings
from .database import Attachment, Database
from .services import MinioObjectStore, ObjectStore, RedisJobQueue


logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger("ruby-web-worker")


def process_one_attachment(database: Database, objects: ObjectStore, attachment_id: str) -> bool:
    with database.sessions() as session:
        record = session.get(Attachment, attachment_id)
        if record is None:
            LOGGER.warning("attachment job references missing row: %s", attachment_id)
            return False
        try:
            record.status = "available" if objects.exists(record.object_key) else "failed"
        except Exception:
            LOGGER.exception("attachment object check failed: %s", attachment_id)
            record.status = "failed"
        session.commit()
        return record.status == "available"


def run() -> None:
    settings = Settings.from_environment()
    database = Database(settings.database_url)
    redis_client = Redis.from_url(settings.redis_url)
    queue = RedisJobQueue(redis_client)
    objects = MinioObjectStore(
        Minio(
            settings.object_endpoint,
            access_key=settings.object_access_key,
            secret_key=settings.object_secret_key,
            secure=settings.object_secure,
        ),
        settings.object_bucket,
    )
    LOGGER.info("attachment worker started")
    while True:
        attachment_id = queue.next_attachment(timeout_seconds=5)
        if attachment_id is None:
            time.sleep(0.25)
            continue
        process_one_attachment(database, objects, attachment_id)


if __name__ == "__main__":
    run()
