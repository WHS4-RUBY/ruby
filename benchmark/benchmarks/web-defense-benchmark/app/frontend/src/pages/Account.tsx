import { FormEvent, useEffect, useState } from "react";
import { ApiError, Order, User, get, money, send, when } from "../api";

export function Account({
  user,
  onUser,
  notify,
}: {
  user: User | null;
  onUser: (user: User | null) => void;
  notify: (text: string, problem?: boolean) => void;
}) {
  const [orders, setOrders] = useState<Order[]>([]);

  async function reloadOrders() {
    if (user?.role !== "customer") {
      setOrders([]);
      return;
    }
    try {
      setOrders(await get<Order[]>("/api/orders"));
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  useEffect(() => {
    reloadOrders();
  }, [user?.id, user?.role]);

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/auth/register", {
        email: form.get("email"),
        display_name: form.get("display_name"),
        password: form.get("password"),
      });
      (event.target as HTMLFormElement).reset();
      notify("계정을 만들었습니다. 이제 로그인하세요.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function updateProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const updated = await send<User>("PATCH", "/api/me/profile", {
        display_name: form.get("display_name"),
      });
      onUser(updated);
      notify("표시 이름을 바꿨습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function rememberDevice() {
    try {
      await send("POST", "/api/auth/remember-device");
      notify("이 기기를 기억합니다. 다음에는 로그인 없이 이어서 쓸 수 있습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function requestReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/auth/password-reset/request", {
        email: form.get("email"),
      });
      notify("등록된 주소로 재설정 안내를 보냈습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function confirmReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/auth/password-reset/confirm", {
        token: form.get("token"),
        new_password: form.get("new_password"),
      });
      (event.target as HTMLFormElement).reset();
      notify("비밀번호를 바꿨습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function act(path: string, body?: unknown, done?: string) {
    try {
      await send("POST", path, body);
      notify(done ?? "처리했습니다.");
      await reloadOrders();
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  return (
    <>
      {user && (
        <section>
          <h2>내 계정</h2>
          <div className="panel stack">
            <p>
              {user.display_name} <span className="badge">{user.role}</span>
              <span className="muted"> {user.email}</span>
            </p>
            <form className="inline" onSubmit={updateProfile}>
              <label>
                표시 이름
                <input
                  name="display_name"
                  defaultValue={user.display_name}
                  minLength={2}
                  maxLength={80}
                  required
                />
              </label>
              <button type="submit">저장</button>
              <button type="button" className="secondary" onClick={rememberDevice}>
                이 기기 기억하기
              </button>
            </form>
          </div>
        </section>
      )}

      {user?.role === "customer" && (
        <section>
          <h2>주문 내역</h2>
          <table className="panel">
            <thead>
              <tr>
                <th>주문</th>
                <th>상태</th>
                <th>합계</th>
                <th>결제</th>
                <th>처리</th>
              </tr>
            </thead>
            <tbody>
              {orders.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    아직 주문이 없습니다.
                  </td>
                </tr>
              )}
              {orders.map((order) => (
                <tr key={order.id}>
                  <td>
                    <code>{order.id.slice(0, 8)}</code>
                    <div className="muted">
                      {order.items
                        .map((line) => `${line.product_id} x${line.quantity}`)
                        .join(", ")}
                    </div>
                    <div className="muted">{when(order.created_at)}</div>
                  </td>
                  <td>
                    <span className="badge">{order.status}</span>
                  </td>
                  <td>{money(order.total_cents)}</td>
                  <td className="muted">{order.payment_method ?? "미결제"}</td>
                  <td>
                    <div className="row">
                      {order.status === "pending_payment" && (
                        <button
                          type="button"
                          onClick={() =>
                            act(
                              `/api/orders/${order.id}/pay`,
                              { method: "wallet" },
                              "결제했습니다.",
                            )
                          }
                        >
                          결제
                        </button>
                      )}
                      {(order.status === "pending_payment" ||
                        order.status === "paid") && (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() =>
                            act(
                              `/api/orders/${order.id}/cancel`,
                              undefined,
                              "주문을 취소하고 결제를 되돌렸습니다.",
                            )
                          }
                        >
                          취소
                        </button>
                      )}
                      {order.status === "shipped" && (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() =>
                            act(
                              `/api/orders/${order.id}/refund-request`,
                              undefined,
                              "반품을 요청했습니다.",
                            )
                          }
                        >
                          반품 요청
                        </button>
                      )}
                      {order.status === "refund_requested" && (
                        <>
                          <button
                            type="button"
                            className="secondary"
                            onClick={() =>
                              act(
                                `/api/orders/${order.id}/refund`,
                                undefined,
                                "환불을 받았습니다.",
                              )
                            }
                          >
                            즉시 환불 받기
                          </button>
                          <span className="muted">또는 판매자 승인 대기</span>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">
            발송 전에는 취소로 결제를 되돌립니다. 반품은 물건을 받은 뒤에
            요청합니다.
          </p>
        </section>
      )}

      {!user && (
        <section>
          <h2>회원 가입</h2>
          <form className="stacked panel" onSubmit={register}>
            <label>
              이메일
              <input name="email" type="email" required />
            </label>
            <label>
              표시 이름
              <input name="display_name" required minLength={2} maxLength={80} />
            </label>
            <label>
              비밀번호
              <input
                name="password"
                type="password"
                required
                minLength={12}
                maxLength={128}
              />
            </label>
            <button type="submit">가입</button>
          </form>
        </section>
      )}

      <section>
        <h2>비밀번호 재설정</h2>
        <div className="grid">
          <form className="stacked panel" onSubmit={requestReset}>
            <h3>재설정 안내 받기</h3>
            <label>
              가입한 이메일
              <input name="email" type="email" required />
            </label>
            <button type="submit">안내 보내기</button>
          </form>
          <form className="stacked panel" onSubmit={confirmReset}>
            <h3>새 비밀번호 정하기</h3>
            <label>
              안내에 적힌 토큰
              <input name="token" required minLength={20} maxLength={256} />
            </label>
            <label>
              새 비밀번호
              <input
                name="new_password"
                type="password"
                required
                minLength={12}
                maxLength={128}
              />
            </label>
            <button type="submit">변경</button>
          </form>
        </div>
      </section>
    </>
  );
}
