import { useEffect, useState } from "react";
import { ApiError, User, get, money, send, when } from "../api";

type OperationsStatus = {
  status: string;
  services: string[];
  details?: Record<string, string> | null;
};

type OperationsMetrics = {
  generated_at: string;
  paid_order_count: number;
  settlement_total_cents: number;
  seller_revenue_cents: Record<string, number>;
};

const ROLES = ["customer", "seller_staff", "support_staff", "admin"];

export function Operations({
  user,
  notify,
}: {
  user: User | null;
  notify: (text: string, problem?: boolean) => void;
}) {
  const admin = user?.role === "admin";
  const [status, setStatus] = useState<OperationsStatus | null>(null);
  const [metrics, setMetrics] = useState<OperationsMetrics | null>(null);
  const [people, setPeople] = useState<User[]>([]);

  useEffect(() => {
    get<OperationsStatus>("/api/operations/status")
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  async function reload() {
    if (!admin) {
      setPeople([]);
      setMetrics(null);
      return;
    }
    try {
      const [users, figures] = await Promise.all([
        get<User[]>("/api/admin/users"),
        get<OperationsMetrics>("/api/operations/metrics"),
      ]);
      setPeople(users);
      setMetrics(figures);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  useEffect(() => {
    reload();
  }, [user?.id, user?.role]);

  async function changeRole(target: User, role: string) {
    try {
      await send("PATCH", `/api/admin/users/${target.id}/role`, { role });
      await reload();
      notify(`${target.display_name} 의 역할을 ${role} 로 바꿨습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function setActive(target: User, active: boolean) {
    try {
      await send("PATCH", `/api/admin/users/${target.id}`, { active });
      await reload();
      notify(`${target.display_name} 계정을 ${active ? "다시 열었" : "잠갔"}습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  return (
    <>
      <section>
        <h2>서비스 상태</h2>
        <div className="panel">
          {status === null ? (
            <p className="muted">상태를 불러오지 못했습니다.</p>
          ) : (
            <>
              <p>
                <span className="badge">{status.status}</span>
              </p>
              <p className="muted">서비스: {status.services.join(", ")}</p>
            </>
          )}
        </div>
      </section>

      {!admin && (
        <section>
          <p className="muted">
            사용자와 정산 관리는 운영자 계정으로 로그인해야 보입니다.
          </p>
        </section>
      )}

      {admin && (
        <>
          <section>
            <h2>정산 요약</h2>
            <div className="panel">
              {metrics === null ? (
                <p className="muted">집계가 없습니다.</p>
              ) : (
                <>
                  <p>
                    결제 완료 {metrics.paid_order_count} 건, 합계{" "}
                    {money(metrics.settlement_total_cents)}
                  </p>
                  <p className="muted">기준 시각 {when(metrics.generated_at)}</p>
                  <table>
                    <thead>
                      <tr>
                        <th>상점</th>
                        <th>매출</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(metrics.seller_revenue_cents).map(
                        ([shop, amount]) => (
                          <tr key={shop}>
                            <td className="muted">{shop}</td>
                            <td>{money(amount)}</td>
                          </tr>
                        ),
                      )}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          </section>

          <section>
            <h2>사용자 관리</h2>
            <table className="panel">
              <thead>
                <tr>
                  <th>사람</th>
                  <th>역할</th>
                  <th>상태</th>
                  <th>처리</th>
                </tr>
              </thead>
              <tbody>
                {people.map((person) => (
                  <tr key={person.id}>
                    <td>
                      {person.display_name}
                      <div className="muted">{person.email}</div>
                    </td>
                    <td>
                      <select
                        value={person.role}
                        onChange={(event) => changeRole(person, event.target.value)}
                      >
                        {ROLES.map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <span className="badge">
                        {person.active ? "활성" : "잠김"}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => setActive(person, !person.active)}
                      >
                        {person.active ? "잠그기" : "열기"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted">
              접근 권한 변경은 알림에 실린 승인 링크로도 처리합니다.
            </p>
          </section>
        </>
      )}
    </>
  );
}
