import { FormEvent, useEffect, useState } from "react";
import {
  ApiError,
  SellerDocument,
  Ticket,
  User,
  get,
  send,
  upload,
  when,
} from "../api";

type Diagnostic = {
  ticket_id: string;
  error_code: string;
  message: string;
  debug_context?: Record<string, string> | null;
};

type GuestInquiry = {
  id: string;
  email: string;
  subject: string;
  body: string;
  status: string;
  created_at: string;
};

export function Support({
  user,
  notify,
}: {
  user: User | null;
  notify: (text: string, problem?: boolean) => void;
}) {
  const staff = user?.role === "support_staff" || user?.role === "admin";
  const [queue, setQueue] = useState<Ticket[]>([]);
  const [inquiries, setInquiries] = useState<GuestInquiry[]>([]);
  const [documents, setDocuments] = useState<SellerDocument[]>([]);
  const [open, setOpen] = useState<Ticket | null>(null);
  const [lookup, setLookup] = useState<User | null>(null);
  const [diagnostic, setDiagnostic] = useState<Diagnostic | null>(null);
  const [exported, setExported] = useState<string[] | null>(null);

  async function reload() {
    if (!staff) {
      setQueue([]);
      setInquiries([]);
      setDocuments([]);
      return;
    }
    try {
      const [tickets, guests, docs] = await Promise.all([
        get<Ticket[]>("/api/support/tickets"),
        get<GuestInquiry[]>("/api/support/guest-inquiries"),
        get<SellerDocument[]>("/api/support/documents"),
      ]);
      setQueue(tickets);
      setInquiries(guests);
      setDocuments(docs);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  useEffect(() => {
    reload();
  }, [user?.id, user?.role]);

  async function createTicket(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await upload<Ticket>("/api/tickets", form);
      (event.target as HTMLFormElement).reset();
      notify("문의를 등록했습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function openTicket(ticketId: string) {
    try {
      setOpen(await get<Ticket>(`/api/tickets/${ticketId}`));
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function reply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!open) return;
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", `/api/tickets/${open.id}/messages`, {
        body: form.get("body"),
      });
      (event.target as HTMLFormElement).reset();
      await openTicket(open.id);
      notify("답변을 남겼습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function setStatus(ticketId: string, status: string) {
    try {
      await send("PATCH", `/api/tickets/${ticketId}/status`, { status });
      await reload();
      if (open?.id === ticketId) {
        await openTicket(ticketId);
      }
      notify(`문의 상태를 ${status} 로 바꿨습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function setInquiryStatus(inquiryId: string, status: string) {
    try {
      await send("PATCH", `/api/support/guest-inquiries/${inquiryId}`, {
        status,
      });
      await reload();
      notify("비회원 문의 상태를 바꿨습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function lookupCustomer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      setLookup(
        await get<User>(
          `/api/customers/${String(form.get("customer_id"))}/profile`,
        ),
      );
    } catch (error) {
      setLookup(null);
      notify((error as ApiError).message, true);
    }
  }

  async function readDiagnostic(ticketId: string) {
    try {
      setDiagnostic(
        await get<Diagnostic>(
          `/api/support/tickets/${ticketId}/error-diagnostic`,
        ),
      );
    } catch (error) {
      setDiagnostic(null);
      notify((error as ApiError).message, true);
    }
  }

  async function exportDiagnostics(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!open) return;
    const form = new FormData(event.currentTarget);
    const selectors = String(form.get("arguments") ?? "")
      .split(/[\s,]+/)
      .filter((item) => item.length > 0)
      .slice(0, 10);
    try {
      const result = await send<{ lines: string[] }>(
        "POST",
        `/api/support/tickets/${open.id}/diagnostic-export`,
        { arguments: selectors },
      );
      setExported(result.lines);
    } catch (error) {
      setExported(null);
      notify((error as ApiError).message, true);
    }
  }

  return (
    <>
      {user?.role === "customer" && (
        <section>
          <h2>문의 등록</h2>
          <form className="stacked panel" onSubmit={createTicket}>
            <label>
              제목
              <input name="subject" required minLength={3} maxLength={160} />
            </label>
            <label>
              내용
              <textarea name="body" required minLength={3} maxLength={5000} />
            </label>
            <label>
              첨부 (선택)
              <input name="attachment" type="file" />
            </label>
            <button type="submit">등록</button>
          </form>
        </section>
      )}

      {staff && (
        <>
          <section>
            <h2>상담 대기열</h2>
            <table className="panel">
              <thead>
                <tr>
                  <th>제목</th>
                  <th>등록</th>
                  <th>상태</th>
                  <th>처리</th>
                </tr>
              </thead>
              <tbody>
                {queue.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      대기 중인 문의가 없습니다.
                    </td>
                  </tr>
                )}
                {queue.map((ticket) => (
                  <tr key={ticket.id}>
                    <td>{ticket.subject}</td>
                    <td className="muted">{when(ticket.created_at)}</td>
                    <td>
                      <span className="badge">{ticket.status}</span>
                    </td>
                    <td>
                      <div className="row">
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => openTicket(ticket.id)}
                        >
                          열기
                        </button>
                        <a
                          className="badge"
                          href={`/api/support/tickets/${ticket.id}/html-preview`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          서식 미리보기
                        </a>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => readDiagnostic(ticket.id)}
                        >
                          진단
                        </button>
                        {ticket.status === "open" && (
                          <button
                            type="button"
                            onClick={() => setStatus(ticket.id, "resolved")}
                          >
                            해결 처리
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section>
            <h2>비회원 문의</h2>
            <table className="panel">
              <thead>
                <tr>
                  <th>보낸 사람</th>
                  <th>제목</th>
                  <th>상태</th>
                  <th>처리</th>
                </tr>
              </thead>
              <tbody>
                {inquiries.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      비회원 문의가 없습니다.
                    </td>
                  </tr>
                )}
                {inquiries.map((item) => (
                  <tr key={item.id}>
                    <td className="muted">{item.email}</td>
                    <td>
                      {item.subject}
                      <div className="muted">{item.body}</div>
                    </td>
                    <td>
                      <span className="badge">{item.status}</span>
                    </td>
                    <td>
                      {item.status === "open" && (
                        <button
                          type="button"
                          onClick={() => setInquiryStatus(item.id, "resolved")}
                        >
                          해결 처리
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          {diagnostic && (
            <section>
              <h2>서식 오류 진단</h2>
              <div className="panel">
                <p>
                  <span className="badge">{diagnostic.error_code}</span>{" "}
                  {diagnostic.message}
                </p>
                {diagnostic.debug_context && (
                  <table>
                    <tbody>
                      {Object.entries(diagnostic.debug_context).map(
                        ([key, value]) => (
                          <tr key={key}>
                            <th>{key}</th>
                            <td className="muted">{value}</td>
                          </tr>
                        ),
                      )}
                    </tbody>
                  </table>
                )}
                <button
                  type="button"
                  className="secondary"
                  onClick={() => setDiagnostic(null)}
                >
                  닫기
                </button>
              </div>
            </section>
          )}

          <section>
            <h2>고객 조회</h2>
            <form className="inline panel" onSubmit={lookupCustomer}>
              <label>
                고객 식별자
                <input name="customer_id" required />
              </label>
              <button type="submit">조회</button>
              {lookup && (
                <span className="muted">
                  {lookup.display_name} {lookup.email}{" "}
                  <span className="badge">{lookup.role}</span>
                </span>
              )}
            </form>
          </section>

          <section>
            <h2>판매자가 올린 문서</h2>
            <table className="panel">
              <thead>
                <tr>
                  <th>파일</th>
                  <th>상품</th>
                  <th>크기</th>
                  <th>보기</th>
                </tr>
              </thead>
              <tbody>
                {documents.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      올라온 문서가 없습니다.
                    </td>
                  </tr>
                )}
                {documents.map((document) => (
                  <tr key={document.id}>
                    <td>{document.original_name}</td>
                    <td className="muted">{document.product_id}</td>
                    <td className="muted">{document.size_bytes} 바이트</td>
                    <td>
                      <a
                        className="badge"
                        href={`/api/support/documents/${document.id}/preview`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        미리보기
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}

      {open && (
        <section>
          <h2>문의 상세</h2>
          <div className="panel stack">
            <div>
              <h3>{open.subject}</h3>
              <p>{open.body}</p>
              <p className="muted">
                고객 {open.customer_id}, 상태 {open.status}
              </p>
            </div>
            {(open.attachments ?? []).length > 0 && (
              <p className="muted">
                첨부:{" "}
                {(open.attachments ?? [])
                  .map((item) => item.original_name)
                  .join(", ")}
              </p>
            )}
            <div className="stack">
              {(open.messages ?? []).map((message) => (
                <div key={message.id} className="notice">
                  {message.body}
                  <div className="muted">{when(message.created_at)}</div>
                </div>
              ))}
            </div>
            <form className="inline" onSubmit={exportDiagnostics}>
              <label>
                진단 항목
                <input
                  name="arguments"
                  defaultValue="ticket messages orders"
                  required
                />
              </label>
              <button type="submit" className="secondary">
                진단 묶음 내보내기
              </button>
            </form>
            {exported && (
              <pre className="notice">{exported.join(String.fromCharCode(10))}</pre>
            )}
            <form className="stacked" onSubmit={reply}>
              <label>
                답변
                <textarea name="body" required minLength={1} maxLength={5000} />
              </label>
              <div className="row">
                <button type="submit">보내기</button>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => setOpen(null)}
                >
                  닫기
                </button>
              </div>
            </form>
          </div>
        </section>
      )}
    </>
  );
}
