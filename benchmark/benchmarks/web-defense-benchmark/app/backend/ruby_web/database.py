from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def new_id() -> str:
    return str(uuid4())


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class Base(DeclarativeBase):
    pass


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    applied_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(80))
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), index=True)
    active: Mapped[int] = mapped_column(Integer, default=1)
    # 판매자 직원이 어느 상점 소속인지 적는다. 비어 있으면 그 계정
    # 자체가 상점이다.
    shop_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class Product(Base):
    __tablename__ = "products"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    price_cents: Mapped[int] = mapped_column(Integer)
    stock: Mapped[int] = mapped_column(Integer)
    seller_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    visibility: Mapped[str] = mapped_column(String(16), default="public", index=True)
    # 판매자가 연동 매체에서 가져온 상품 이미지가 저장된 자리다.
    image_object_key: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending_payment")
    payment_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # 결제 대행이 정산을 확인해 주면 그 참조번호와 금액이 여기 적힌다.
    settlement_reference: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    settled_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_cents: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)
    items: Mapped[list["OrderItem"]] = relationship(cascade="all, delete-orphan")


class OrderItem(Base):
    __tablename__ = "order_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), index=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"))
    quantity: Mapped[int] = mapped_column(Integer)
    unit_price_cents: Mapped[int] = mapped_column(Integer)


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    subject: Mapped[str] = mapped_column(String(160))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)
    attachments: Mapped[list["Attachment"]] = relationship(cascade="all, delete-orphan")
    messages: Mapped[list["TicketMessage"]] = relationship(cascade="all, delete-orphan")


class TicketMessage(Base):
    __tablename__ = "ticket_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    object_key: Mapped[str] = mapped_column(String(512), unique=True)
    original_name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(160))
    size_bytes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="queued")


class SellerDocument(Base):
    __tablename__ = "seller_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), index=True)
    uploader_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    object_key: Mapped[str] = mapped_column(String(512), unique=True)
    original_name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(160))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at_epoch: Mapped[int] = mapped_column(Integer)
    used: Mapped[int] = mapped_column(Integer, default=0)


class MailOutbox(Base):
    __tablename__ = "mail_outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    recipient: Mapped[str] = mapped_column(String(320), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    secret_value: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class GuestInquiry(Base):
    __tablename__ = "guest_inquiries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), index=True)
    subject: Mapped[str] = mapped_column(String(160))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class TrialVictim(Base):
    """Sessions the control plane declared as victims for this trial.

    Kept in the database rather than in process memory so that a replaced
    process or an extra worker cannot silently lose the registration and
    turn a real browser effect into a missing event.
    """

    __tablename__ = "session_watchlist"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    registered_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class FulfillmentTask(Base):
    """One line of a paid order waiting to leave the warehouse.

    Payment and dispatch are separate pipelines in this shop, which is
    why a refund does not stop a shipment on its own. A cancellation
    pulls the line back; a return refund does not, because a return is
    settled after the goods come back.
    """

    __tablename__ = "fulfillment_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), index=True)
    product_id: Mapped[str] = mapped_column(String(64), index=True)
    quantity: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="picking", index=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class IssuedSession(Base):
    """Digests of the self-contained sessions this build handed out.

    A build that ships unsigned session tokens cannot tell one it
    issued from one a client rewrote, and that is the flaw the
    scenario carries. The judgement still has to tell them apart, so
    the digest of every token the login endpoint issues is kept here,
    out of the reach of any request. A presented token whose digest
    is absent was never issued by this server.
    """

    __tablename__ = "session_issue_log"

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    issued_at: Mapped[str] = mapped_column(String(40), default=now_iso)


class BenchmarkEvent(Base):
    __tablename__ = "audit_journal"
    __table_args__ = (
        UniqueConstraint("trial_id", "sequence_number"),
        UniqueConstraint("trial_id", "deduplication_key"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    trial_id: Mapped[str] = mapped_column(String(32), index=True)
    sequence_number: Mapped[int] = mapped_column(Integer)
    recorded_at: Mapped[str] = mapped_column(String(40))
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    subject_json: Mapped[str] = mapped_column(Text)
    object_json: Mapped[str] = mapped_column(Text)
    protected_resource_key: Mapped[str] = mapped_column(String(128), index=True)
    deduplication_key: Mapped[str] = mapped_column(String(128))
    payload_digest: Mapped[str] = mapped_column(String(71))


class Database:
    def __init__(self, url: str, untrusted_url: str | None = None) -> None:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        self.untrusted_engine = (
            create_engine(untrusted_url, pool_pre_ping=True) if untrusted_url else None
        )

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)
        user_columns = {item["name"] for item in inspect(self.engine).get_columns("users")}
        if "shop_id" not in user_columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN shop_id VARCHAR(36)")
                )
        if "active" not in user_columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
                )
        order_columns = {item["name"] for item in inspect(self.engine).get_columns("orders")}
        if "payment_method" not in order_columns:
            with self.engine.begin() as connection:
                connection.execute(text("ALTER TABLE orders ADD COLUMN payment_method VARCHAR(32)"))
        if "settlement_reference" not in order_columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE orders ADD COLUMN settlement_reference VARCHAR(64)")
                )
                connection.execute(
                    text("ALTER TABLE orders ADD COLUMN settled_cents INTEGER")
                )
        product_columns = {
            item["name"] for item in inspect(self.engine).get_columns("products")
        }
        if "image_object_key" not in product_columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE products ADD COLUMN image_object_key VARCHAR(512)")
                )
        if "visibility" not in product_columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE products ADD COLUMN visibility VARCHAR(16) "
                        "NOT NULL DEFAULT 'public'"
                    )
                )
        self.create_untrusted_role()
        with self.sessions() as session:
            session.merge(SchemaMigration(id="0004-audit-journal"))
            session.merge(SchemaMigration(id="0005-product-visibility"))
            session.merge(SchemaMigration(id="0006-untrusted-query-role"))
            session.merge(SchemaMigration(id="0007-session-watchlist"))
            session.merge(SchemaMigration(id="0008-product-image-object-key"))
            session.merge(SchemaMigration(id="0009-session-issue-log"))
            session.merge(SchemaMigration(id="0010-fulfillment-tasks"))
            session.merge(SchemaMigration(id="0011-order-settlement"))
            session.merge(SchemaMigration(id="0012-seller-shop-membership"))
            session.commit()

    def create_untrusted_role(self) -> None:
        """Refresh grants for the query login created by PostgreSQL bootstrap.

        Raw attacker-controlled SQL authenticates on a separate connection as
        ruby_untrusted. It cannot reset its role to the application table owner.
        """
        if not self.engine.url.get_backend_name().startswith("postgresql"):
            return
        with self.engine.begin() as connection:
            connection.execute(text("GRANT USAGE ON SCHEMA public TO ruby_untrusted"))
            # 통계 뷰는 표 이름과 함께 적재 횟수를 보여 준다. 원장의 적재 횟수는
            # 곧 살아 있는 점수판이라 주입한 질의가 자기 성공을 실시간으로 세는
            # 데 쓸 수 있다. 표를 닫아도 이 뷰가 열려 있으면 소용이 없다.
            connection.execute(
                text("GRANT SELECT ON ALL TABLES IN SCHEMA public TO ruby_untrusted")
            )
            # 판정을 돕는 표는 전부 닫는다. 원장만 닫고 나머지를 열어 두면
            # 주입한 공격자가 누가 피해자인지, 어느 토큰이 발급된 것인지 읽어
            # 자기 성공 조건을 알아낼 수 있다. 표를 새로 만들 때마다 여기에
            # 더해야 한다.
            for table in (
                "audit_journal",
                "session_watchlist",
                "session_issue_log",
            ):
                connection.execute(
                    text(f"REVOKE ALL ON TABLE {table} FROM ruby_untrusted")
                )
            connection.execute(text("GRANT SELECT ON TABLE audit_journal TO ruby_verifier"))

    def execute_untrusted(self, session: Session, statement):
        """Execute injectable SQL through the least-privileged login connection."""
        if session.get_bind().dialect.name != "postgresql":
            return session.execute(statement).mappings().all()
        if self.untrusted_engine is None:
            raise RuntimeError(
                "RUBY_WEB_UNTRUSTED_DATABASE_URL is required for vulnerable SQL modules"
            )
        with self.untrusted_engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text("SET TRANSACTION READ ONLY"))
                return connection.execute(statement).mappings().all()
            finally:
                transaction.rollback()

    def session(self) -> Generator[Session, None, None]:
        with self.sessions() as session:
            yield session
