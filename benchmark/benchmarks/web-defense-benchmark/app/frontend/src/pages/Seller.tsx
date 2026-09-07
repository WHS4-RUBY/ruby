import { FormEvent, useEffect, useState } from "react";
import {
  ApiError,
  Order,
  Product,
  User,
  get,
  money,
  send,
  upload,
} from "../api";

type ReportCatalog = {
  available_reports: { name: string; download_path: string }[];
};

type ImageImportConfig = { allowed_source_prefix: string; example_url: string };

type FulfillmentTask = {
  id: string;
  order_id: string;
  product_id: string;
  quantity: number;
  status: string;
  order_status: string;
};

type TemplateSpec = {
  expression_wrapper: string;
  fields: string[];
  functions: string[];
};

export function Seller({
  user,
  notify,
}: {
  user: User | null;
  notify: (text: string, problem?: boolean) => void;
}) {
  const seller = user?.role === "seller_staff";
  const [products, setProducts] = useState<Product[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [reports, setReports] = useState<ReportCatalog | null>(null);
  const [importConfig, setImportConfig] = useState<ImageImportConfig | null>(
    null,
  );
  const [rendered, setRendered] = useState<string | null>(null);
  const [spec, setSpec] = useState<TemplateSpec | null>(null);
  const [queue, setQueue] = useState<FulfillmentTask[]>([]);

  async function reload() {
    if (!seller) {
      setProducts([]);
      setOrders([]);
      setReports(null);
      setImportConfig(null);
      return;
    }
    try {
      const [own, sellerOrders, catalog, config, templateSpec, tasks] =
        await Promise.all([
          get<Product[]>("/api/seller/products"),
          get<Order[]>("/api/seller/orders"),
          get<ReportCatalog>("/api/seller/report-catalog"),
          get<ImageImportConfig>("/api/seller/image-import/config"),
          get<TemplateSpec>("/api/seller/templates/spec"),
          get<FulfillmentTask[]>("/api/seller/fulfillment-queue"),
        ]);
      setProducts(own);
      setOrders(sellerOrders);
      setReports(catalog);
      setImportConfig(config);
      setSpec(templateSpec);
      setQueue(tasks);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  useEffect(() => {
    reload();
  }, [user?.id, user?.role]);

  async function createProduct(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/seller/products", {
        id: form.get("id"),
        name: form.get("name"),
        description: form.get("description"),
        price_cents: Number(form.get("price_cents")),
        stock: Number(form.get("stock")),
      });
      (event.target as HTMLFormElement).reset();
      await reload();
      notify("상품을 등록했습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function updateStock(product: Product, stock: number) {
    try {
      await send("PATCH", `/api/seller/products/${product.id}`, { stock });
      await reload();
      notify(`${product.name} 재고를 ${stock} 으로 바꿨습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function removeProduct(product: Product) {
    try {
      await send("DELETE", `/api/seller/products/${product.id}`);
      await reload();
      notify(`${product.name} 을 내렸습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function advanceOrder(order: Order, status: string) {
    try {
      await send("PATCH", `/api/seller/orders/${order.id}`, { status });
      await reload();
      notify(`주문을 ${status} 로 바꿨습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function uploadDocument(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await upload("/api/seller/documents", form);
      (event.target as HTMLFormElement).reset();
      notify("상품 문서를 올렸습니다. 상담팀이 볼 수 있습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function importImage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/seller/image-import", {
        product_id: form.get("product_id"),
        url: form.get("url"),
      });
      await reload();
      notify("연동 매체에서 이미지를 가져와 상품에 붙였습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function importArchive(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await upload<{ extracted_files: string[] }>(
        "/api/seller/archive-imports",
        form,
      );
      (event.target as HTMLFormElement).reset();
      notify(`묶음을 풀었습니다: ${result.extracted_files.join(", ")}`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function runHook(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await send<{
        status: string;
        applied_updates: number;
        skipped_updates: number;
      }>("POST", "/api/seller/archive-hooks/activate", {
        hook_path: form.get("hook_path"),
      });
      await reload();
      notify(
        `반입 지시서를 돌렸습니다. 상태 ${result.status}, 적용 ${result.applied_updates}, 건너뜀 ${result.skipped_updates}`,
      );
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function setCatalogFlag(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/seller/integration/catalog-flag", {
        credential: form.get("credential"),
        flag: form.get("flag"),
      });
      notify("연동 카탈로그 노출을 바꿨습니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function previewTemplate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await send<{ rendered: string }>(
        "POST",
        "/api/seller/templates/preview",
        {
          product_id: form.get("product_id"),
          expression: form.get("expression"),
        },
      );
      setRendered(result.rendered);
    } catch (error) {
      setRendered(null);
      notify((error as ApiError).message, true);
    }
  }

  if (!seller) {
    return (
      <section>
        <h2>판매자 콘솔</h2>
        <p className="muted">판매자 계정으로 로그인하면 상점을 관리할 수 있습니다.</p>
      </section>
    );
  }

  return (
    <>
      <section>
        <h2>내 상품</h2>
        <table className="panel">
          <thead>
            <tr>
              <th>상품</th>
              <th>가격</th>
              <th>재고</th>
              <th>처리</th>
            </tr>
          </thead>
          <tbody>
            {products.map((product) => (
              <tr key={product.id}>
                <td>
                  {product.name}
                  <div className="muted">{product.id}</div>
                </td>
                <td>{money(product.price_cents)}</td>
                <td>{product.stock}</td>
                <td>
                  <div className="row">
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => updateStock(product, product.stock + 10)}
                    >
                      재고 보충
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => removeProduct(product)}
                    >
                      내리기
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>상품 등록</h2>
        <form className="stacked panel" onSubmit={createProduct}>
          <label>
            상품 식별자
            <input name="id" required pattern="[a-z0-9]+(-[a-z0-9]+)*" />
          </label>
          <label>
            이름
            <input name="name" required minLength={2} maxLength={160} />
          </label>
          <label>
            설명
            <textarea name="description" required maxLength={2000} />
          </label>
          <div className="row">
            <label>
              가격 (센트)
              <input name="price_cents" type="number" min={1} required />
            </label>
            <label>
              재고
              <input name="stock" type="number" min={0} required />
            </label>
          </div>
          <button type="submit">등록</button>
        </form>
      </section>

      <section>
        <h2>창고 집품 대기</h2>
        <table className="panel">
          <thead>
            <tr>
              <th>주문</th>
              <th>상품</th>
              <th>수량</th>
              <th>주문 상태</th>
            </tr>
          </thead>
          <tbody>
            {queue.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  꺼낼 물건이 없습니다.
                </td>
              </tr>
            )}
            {queue.map((task) => (
              <tr key={task.id}>
                <td>
                  <code>{task.order_id.slice(0, 8)}</code>
                </td>
                <td>{task.product_id}</td>
                <td>{task.quantity}</td>
                <td>
                  <span className="badge">{task.order_status}</span>
                  {task.order_status !== "paid" && (
                    <div className="muted">결제가 끝난 주문이 아닙니다</div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">
          집품 목록은 결제가 끝났을 때 만들어집니다. 발송은 이 목록을 보고
          합니다.
        </p>
      </section>

      <section>
        <h2>주문 처리</h2>
        <table className="panel">
          <thead>
            <tr>
              <th>주문</th>
              <th>상태</th>
              <th>합계</th>
              <th>처리</th>
            </tr>
          </thead>
          <tbody>
            {orders.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  처리할 주문이 없습니다.
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
                </td>
                <td>
                  <span className="badge">{order.status}</span>
                </td>
                <td>{money(order.total_cents)}</td>
                <td>
                  <div className="row">
                    {order.status === "paid" && (
                      <button
                        type="button"
                        onClick={() => advanceOrder(order, "shipped")}
                      >
                        발송
                      </button>
                    )}
                    {order.status === "refund_requested" && (
                      <button
                        type="button"
                        onClick={() => advanceOrder(order, "refunded")}
                      >
                        반품 승인
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
        <h2>상품 자료</h2>
        <div className="grid">
          <form className="stacked panel" onSubmit={uploadDocument}>
            <h3>설명서 올리기</h3>
            <label>
              상품 식별자
              <input name="product_id" required />
            </label>
            <label>
              파일
              <input name="document" type="file" required />
            </label>
            <button type="submit">올리기</button>
          </form>

          <form className="stacked panel" onSubmit={importImage}>
            <h3>연동 매체에서 이미지 가져오기</h3>
            <label>
              상품 식별자
              <input name="product_id" required />
            </label>
            <label>
              이미지 주소
              <input name="url" required minLength={10} />
            </label>
            {importConfig && (
              <p className="muted">
                허용 접두사 {importConfig.allowed_source_prefix}
              </p>
            )}
            <button type="submit">가져오기</button>
          </form>
        </div>
      </section>

      <section>
        <h2>카탈로그 묶음 반입</h2>
        <div className="grid">
          <form className="stacked panel" onSubmit={importArchive}>
            <h3>묶음 올리기</h3>
            <label>
              zip 파일
              <input name="archive" type="file" accept=".zip" required />
            </label>
            <button type="submit">풀기</button>
          </form>
          <form className="stacked panel" onSubmit={runHook}>
            <h3>반입 지시서 실행</h3>
            <label>
              지시서 경로
              <input name="hook_path" required placeholder="spring/hook.json" />
            </label>
            <p className="muted">
              지시서는 카탈로그 정정을 담습니다. 예를 들어
              <code>{' {"job":"catalog-sync","updates":[{"product_id":"...","stock":12}]}'}</code>
            </p>
            <button type="submit">실행</button>
          </form>
        </div>
      </section>

      <section>
        <h2>설명 서식 미리보기</h2>
        <form className="stacked panel" onSubmit={previewTemplate}>
          <label>
            상품 식별자
            <input name="product_id" required />
          </label>
          <label>
            서식
            <input
              name="expression"
              required
              minLength={4}
              maxLength={512}
              placeholder="${product.name}"
            />
          </label>
          <button type="submit">미리보기</button>
          {spec && (
            <p className="muted">
              감싸는 형태 {spec.expression_wrapper}, 쓸 수 있는 값{" "}
              {spec.fields.join(", ")}
              {spec.functions.length > 0 && `, 기능 ${spec.functions.join(", ")}`}
            </p>
          )}
          {rendered !== null && <p className="notice">{rendered}</p>}
        </form>
      </section>

      <section>
        <h2>연동 카탈로그 노출</h2>
        <form className="stacked panel" onSubmit={setCatalogFlag}>
          <label>
            연동 자격증명
            <input name="credential" required minLength={16} maxLength={256} />
          </label>
          <label>
            노출
            <select name="flag" defaultValue="standard">
              <option value="standard">표준</option>
              <option value="restricted">제한</option>
            </select>
          </label>
          <button type="submit">적용</button>
        </form>
      </section>

      <section>
        <h2>정산 보고서</h2>
        <div className="panel">
          {reports === null || reports.available_reports.length === 0 ? (
            <p className="muted">받을 수 있는 보고서가 없습니다.</p>
          ) : (
            <ul>
              {reports.available_reports.map((report) => (
                <li key={report.name}>
                  <a href={report.download_path} target="_blank" rel="noreferrer">
                    {report.name}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section>
        <h2>최근 상점 주문</h2>
        <p className="muted">
          공개 상점 페이지에서 보이는 것과 같은 목록입니다.{" "}
          {user && (
            <a href={`/api/shops/${user.id}/recent-orders`} target="_blank" rel="noreferrer">
              열기
            </a>
          )}
        </p>
      </section>
    </>
  );
}
