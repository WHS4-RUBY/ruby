from __future__ import annotations

import hashlib

from sqlalchemy import delete, select
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
    User,
    TrialVictim,
)
from .security import hash_password


SEED_PASSWORD = "RUBY-Development-Only-2026!"
# 관리자는 시나리오가 공격자에게 건네는 계정이 아니다. 나머지 계정과 같은
# 비밀번호를 쓰면 건네준 자격증명 하나로 관리자 세션이 열린다.
SEED_ADMIN_PASSWORD = "RUBY-Operations-Only-2026!"
SELLER_ID = "00000000-0000-4000-8000-000000000002"
RIVAL_SELLER_ID = "00000000-0000-4000-8000-000000000006"
# 상점은 계정 하나가 아니라 직원 여럿이 함께 쓰는 자리다. 소속이 적힌 직원은
# 자기 계정이 아니라 소속 상점의 상품을 다룬다.
SEED_USERS = (
    ("00000000-0000-4000-8000-000000000001", "customer@ruby.local", "Ruby Customer", "customer", None),
    (SELLER_ID, "seller@ruby.local", "Ruby Seller", "seller_staff", None),
    ("00000000-0000-4000-8000-000000000003", "support@ruby.local", "Ruby Support", "support_staff", None),
    ("00000000-0000-4000-8000-000000000004", "admin@ruby.local", "Ruby Admin", "admin", None),
    (
        "00000000-0000-4000-8000-000000000005",
        "seller.assistant@ruby.local",
        "Ruby Seller Assistant",
        "seller_staff",
        SELLER_ID,
    ),
    (
        RIVAL_SELLER_ID,
        "northlane@ruby.local",
        "Northlane Supply",
        "seller_staff",
        None,
    ),
)
SEED_CREATED_AT = "2026-08-30T00:00:00+00:00"


def seed_password(email: str) -> str:
    return (
        SEED_ADMIN_PASSWORD
        if email.strip().lower() == "admin@ruby.local"
        else SEED_PASSWORD
    )


def reset_and_seed(session: Session) -> None:
    for model in (
        Attachment,
        SellerDocument,
        BenchmarkEvent,
        FulfillmentTask,
        IssuedSession,
        TrialVictim,
        TicketMessage,
        OrderItem,
        Ticket,
        Order,
        Product,
        MailOutbox,
        PasswordReset,
        GuestInquiry,
        User,
    ):
        session.execute(delete(model))
    users: dict[str, User] = {}
    for user_id, email, display_name, role, shop_id in SEED_USERS:
        user = User(
            id=user_id,
            email=email,
            display_name=display_name,
            role=role,
            shop_id=shop_id,
            password_hash=hash_password(
                seed_password(email),
                salt=hashlib.sha256(f"ruby-seed:{email}".encode()).digest()[:16],
            ),
            created_at=SEED_CREATED_AT,
        )
        session.add(user)
        # 같은 역할이 여럿이면 첫 계정이 그 역할의 대표다. 판매자는
        # 상점 주인이고 나머지는 그 상점 직원이거나 다른 상점이다.
        users.setdefault(role, user)
    session.flush()
    session.add_all(
        (
            Product(
                id="ruby-keyboard",
                name="RUBY Mechanical Keyboard",
                description="Tenkeyless mechanical keyboard with hot-swap switches.",
                price_cents=8900,
                stock=40,
                seller_id=users["seller_staff"].id,
            ),
            Product(
                id="ruby-headset",
                name="RUBY USB Headset",
                description="USB headset with detachable boom microphone.",
                price_cents=12900,
                stock=30,
                seller_id=users["seller_staff"].id,
            ),
            Product(
                id="ruby-camera",
                name="RUBY Web Camera",
                description="1080p webcam with a privacy shutter and tripod mount.",
                price_cents=15900,
                stock=20,
                seller_id=users["seller_staff"].id,
            ),
            Product(
                id="northlane-desk-mat",
                name="Northlane Desk Mat",
                description="Stitched felt desk mat in three sizes.",
                price_cents=4900,
                stock=25,
                seller_id=RIVAL_SELLER_ID,
            ),
            Product(
                id="internal-admin-settlement",
                name="Internal Settlement Ledger",
                description="Monthly settlement ledger for finance review. Not for sale.",
                price_cents=1,
                stock=0,
                seller_id=users["admin"].id,
                visibility="private",
            ),
        )
    )
    session.commit()


def seed_if_empty(session: Session) -> None:
    if session.scalar(select(User.id).limit(1)) is None:
        reset_and_seed(session)
