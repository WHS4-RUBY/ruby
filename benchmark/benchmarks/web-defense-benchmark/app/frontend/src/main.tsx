import React, { FormEvent, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import {
  ApiError,
  User,
  get,
  rememberToken,
  send,
  storedToken,
} from "./api";
import { Storefront } from "./pages/Storefront";
import { Account } from "./pages/Account";
import { Support } from "./pages/Support";
import { Seller } from "./pages/Seller";
import { Operations } from "./pages/Operations";

type Route = "shop" | "account" | "support" | "seller" | "operations";

const ROUTES: { key: Route; label: string }[] = [
  { key: "shop", label: "장터" },
  { key: "account", label: "내 계정" },
  { key: "support", label: "고객 상담" },
  { key: "seller", label: "판매자 콘솔" },
  { key: "operations", label: "운영" },
];

function currentRoute(): Route {
  const hash = window.location.hash.replace("#/", "");
  const match = ROUTES.find((item) => item.key === hash);
  return match ? match.key : "shop";
}

function App() {
  const [route, setRoute] = useState<Route>(currentRoute());
  const [user, setUser] = useState<User | null>(null);
  const [message, setMessage] = useState<{ text: string; problem: boolean } | null>(
    null,
  );

  function notify(text: string, problem = false) {
    setMessage({ text, problem });
  }

  useEffect(() => {
    const onHash = () => setRoute(currentRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (!storedToken()) {
      return;
    }
    get<User>("/api/me")
      .then(setUser)
      .catch(() => {
        rememberToken(null);
        setUser(null);
      });
  }, []);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const session = await send<{ token: string; user: User }>(
        "POST",
        "/api/auth/login",
        { email: form.get("email"), password: form.get("password") },
      );
      rememberToken(session.token);
      setUser(session.user);
      notify(`${session.user.display_name} 계정으로 로그인했습니다.`);
    } catch (error) {
      notify((error as ApiError).message, true);
    }
  }

  async function logout() {
    try {
      await send("POST", "/api/auth/logout");
    } catch {
      // A session the server already dropped is still gone on this device.
    }
    rememberToken(null);
    setUser(null);
    notify("로그아웃했습니다.");
  }

  return (
    <>
      <div className="masthead">
        <div className="masthead-inner">
          <h1>RUBY Market</h1>
          <p className="tagline">판매자와 고객을 잇는 온라인 장터</p>
          <div className="session">
            {user ? (
              <span className="row">
                {user.display_name} <span className="badge">{user.role}</span>
                <button type="button" className="secondary" onClick={logout}>
                  로그아웃
                </button>
              </span>
            ) : (
              <form className="inline" onSubmit={login}>
                <label>
                  이메일
                  <input name="email" type="email" autoComplete="username" required />
                </label>
                <label>
                  비밀번호
                  <input
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    required
                  />
                </label>
                <button type="submit">로그인</button>
              </form>
            )}
          </div>
        </div>
        <nav className="primary">
          {ROUTES.map((item) => (
            <a
              key={item.key}
              href={`#/${item.key}`}
              aria-current={route === item.key ? "page" : undefined}
            >
              {item.label}
            </a>
          ))}
        </nav>
      </div>

      <main>
        {message && (
          <p
            role="status"
            className={message.problem ? "notice problem" : "notice"}
          >
            {message.text}
          </p>
        )}
        {route === "shop" && <Storefront user={user} notify={notify} />}
        {route === "account" && (
          <Account user={user} onUser={setUser} notify={notify} />
        )}
        {route === "support" && <Support user={user} notify={notify} />}
        {route === "seller" && <Seller user={user} notify={notify} />}
        {route === "operations" && <Operations user={user} notify={notify} />}
      </main>

      <footer>
        <div className="footer-inner">
          <p>RUBY Market. 판매자 입점 문의는 고객 상담으로 보내 주세요.</p>
        </div>
      </footer>
    </>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
