import { FormEvent, useEffect, useState } from "react";
import {
  ApiError,
  Product,
  get,
  money,
  send,
} from "../api";
import type { User } from "../api";

type SearchResult = { id: string; kind: string; title: string; summary: string };

export function Storefront({
  user,
  notify,
}: {
  user: User | null;
  notify: (text: string, problem?: boolean) => void;
}) {
  const [products, setProducts] = useState<Product[]>([]);
  const [selected, setSelected] = useState<Product | null>(null);
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [quantity, setQuantity] = useState<Record<string, number>>({});

  useEffect(() => {
    get<Product[]>("/api/products")
      .then(setProducts)
      .catch((error: ApiError) => notify(error.message, true));
  }, []);

  async function openDetail(productId: string) {
    try {
      setSelected(await get<Product>(`/api/products/${productId}`));
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const term = String(new FormData(event.currentTarget).get("q") ?? "").trim();
    if (!term) {
      setResults(null);
      return;
    }
    try {
      setResults(
        await get<SearchResult[]>(`/api/search?q=${encodeURIComponent(term)}`),
      );
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function order(product: Product) {
    try {
      await send("POST", "/api/orders", {
        items: [
          { product_id: product.id, quantity: quantity[product.id] ?? 1 },
        ],
      });
      notify(`${product.name} 주문을 접수했습니다. 주문 내역에서 결제하세요.`);
      setProducts(await get<Product[]>("/api/products"));
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function inquire(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await send("POST", "/api/guest-inquiries", {
        email: form.get("email"),
        subject: form.get("subject"),
        body: form.get("body"),
      });
      (event.target as HTMLFormElement).reset();
      notify("문의를 접수했습니다. 상담팀이 회신합니다.");
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  return (
    <>
      <section>
        <h2>상품 찾기</h2>
        <form className="inline panel" onSubmit={search}>
          <label>
            검색어
            <input name="q" placeholder="상품 이름이나 설명" />
          </label>
          <button type="submit">검색</button>
          {results !== null && (
            <button
              type="button"
              className="secondary"
              onClick={() => setResults(null)}
            >
              검색 결과 닫기
            </button>
          )}
        </form>
        {results !== null && (
          <table className="panel" style={{ marginTop: "1rem" }}>
            <thead>
              <tr>
                <th>종류</th>
                <th>제목</th>
                <th>요약</th>
              </tr>
            </thead>
            <tbody>
              {results.length === 0 && (
                <tr>
                  <td colSpan={3} className="muted">
                    찾은 것이 없습니다.
                  </td>
                </tr>
              )}
              {results.map((item) => (
                <tr key={`${item.kind}-${item.id}`}>
                  <td>
                    <span className="badge">{item.kind}</span>
                  </td>
                  <td>{item.title}</td>
                  <td className="muted">{item.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h2>판매 중인 상품</h2>
        <div className="grid">
          {products.map((product) => (
            <article className="card" key={product.id}>
              {product.image_path && (
                <img className="thumb" src={product.image_path} alt="" />
              )}
              <h3>{product.name}</h3>
              <p className="muted">{product.description}</p>
              <p>
                {money(product.price_cents)}
                <span className="badge" style={{ marginLeft: ".5rem" }}>
                  재고 {product.stock}
                </span>
              </p>
              <div className="row">
                <label>
                  수량
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={quantity[product.id] ?? 1}
                    style={{ width: "5rem" }}
                    onChange={(event) =>
                      setQuantity({
                        ...quantity,
                        [product.id]: Number(event.target.value),
                      })
                    }
                  />
                </label>
                <button
                  type="button"
                  onClick={() => order(product)}
                  disabled={user?.role !== "customer"}
                >
                  주문
                </button>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => openDetail(product.id)}
                >
                  상세
                </button>
              </div>
              {user?.role !== "customer" && (
                <p className="muted">주문은 고객 계정으로 로그인해야 합니다.</p>
              )}
            </article>
          ))}
        </div>
      </section>

      {selected && (
        <section>
          <h2>상품 상세</h2>
          <div className="panel">
            <h3>{selected.name}</h3>
            <p>{selected.description}</p>
            <p>
              {money(selected.price_cents)}, 재고 {selected.stock}
            </p>
            <p className="muted">
              판매자 {selected.shop_id}
            </p>
            <div className="row">
              <a
                className="badge"
                href={selected.shop_recent_orders_path}
                target="_blank"
                rel="noreferrer"
              >
                이 상점의 최근 주문
              </a>
              <button
                type="button"
                className="secondary"
                onClick={() => setSelected(null)}
              >
                닫기
              </button>
            </div>
          </div>
        </section>
      )}

      <section>
        <h2>비회원 문의</h2>
        <form className="stacked panel" onSubmit={inquire}>
          <label>
            회신 받을 이메일
            <input name="email" type="email" required />
          </label>
          <label>
            제목
            <input name="subject" required minLength={3} maxLength={160} />
          </label>
          <label>
            내용
            <textarea name="body" required minLength={3} maxLength={5000} />
          </label>
          <button type="submit">문의 보내기</button>
        </form>
      </section>
    </>
  );
}
