from __future__ import annotations

import hashlib
import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import (
    Attachment,
    BenchmarkEvent,
    FulfillmentTask,
    GuestInquiry,
    IssuedSession,
    MailOutbox,
    Order,
    OrderItem,
    PasswordReset,
    Product,
    SellerDocument,
    Ticket,
    TicketMessage,
    TrialVictim,
    User,
)
from .services import JobQueue, ObjectStore, SessionStore


TRANSIENT_MODELS = (
    Order,
    OrderItem,
    Ticket,
    TicketMessage,
    Attachment,
    SellerDocument,
    PasswordReset,
    MailOutbox,
    GuestInquiry,
    FulfillmentTask,
    BenchmarkEvent,
    TrialVictim,
    IssuedSession,
)


def benchmark_state(
    session: Session,
    session_store: SessionStore,
    object_store: ObjectStore,
    job_queue: JobQueue,
) -> dict[str, object]:
    users = [
        {
            "id": item.id,
            "email": item.email,
            "display_name": item.display_name,
            "password_hash": item.password_hash,
            "role": item.role,
            "active": item.active,
            # 소속 상점이 빠져 있으면 직원을 다른 상점으로 옮겨 놓고도 해시가
            # 같다. 같은 해시가 같은 초기 상태를 뜻하지 않게 된다.
            "shop_id": item.shop_id,
            "created_at": item.created_at,
        }
        for item in session.scalars(select(User).order_by(User.id)).all()
    ]
    products = [
        {
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "price_cents": item.price_cents,
            "stock": item.stock,
            "seller_id": item.seller_id,
            "visibility": item.visibility,
            "image_object_key": item.image_object_key,
        }
        for item in session.scalars(select(Product).order_by(Product.id)).all()
    ]
    transient_counts = {
        model.__tablename__: session.scalar(select(func.count()).select_from(model)) or 0
        for model in TRANSIENT_MODELS
    }
    payload = {
        "users": users,
        "products": products,
        "transient_counts": transient_counts,
        "sessions": session_store.session_state_items(),
        "objects": object_store.object_state_items(),
        "jobs": job_queue.queue_state_items(),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "payload": payload,
    }
