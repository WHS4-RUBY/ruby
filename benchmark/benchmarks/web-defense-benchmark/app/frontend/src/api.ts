const TOKEN_KEY = "ruby.session";

export type User = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  active: boolean;
};

export type Product = {
  id: string;
  shop_id: string;
  shop_recent_orders_path: string;
  name: string;
  description: string;
  price_cents: number;
  stock: number;
  image_path?: string | null;
};

export type OrderLine = {
  product_id: string;
  quantity: number;
  unit_price_cents: number;
};

export type Order = {
  id: string;
  status: string;
  total_cents: number;
  payment_method?: string | null;
  created_at: string;
  items: OrderLine[];
};

export type TicketMessage = {
  id: string;
  author_id: string;
  body: string;
  created_at: string;
};

export type Ticket = {
  id: string;
  customer_id: string;
  subject: string;
  body: string;
  status: string;
  created_at: string;
  attachments?: { id: string; original_name: string }[];
  messages?: TicketMessage[];
};

export type SellerDocument = {
  id: string;
  product_id: string;
  original_name: string;
  content_type: string;
  size_bytes: number;
  created_at: string;
};

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function storedToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function rememberToken(token: string | null): void {
  try {
    if (token === null) {
      window.localStorage.removeItem(TOKEN_KEY);
    } else {
      window.localStorage.setItem(TOKEN_KEY, token);
    }
  } catch {
    // A browser that refuses storage still works for one page view.
  }
}

function authorization(): Record<string, string> {
  const token = storedToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function failure(response: Response): Promise<never> {
  let detail = `${response.status}`;
  try {
    const body = await response.json();
    if (body && typeof body.detail === "string") {
      detail = body.detail;
    } else if (Array.isArray(body?.detail)) {
      detail = body.detail
        .map((item: { msg?: string }) => item.msg ?? "invalid value")
        .join(", ");
    }
  } catch {
    // A response without a JSON body keeps the status as its message.
  }
  throw new ApiError(response.status, detail);
}

export async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: authorization() });
  if (!response.ok) {
    return failure(response);
  }
  return (await response.json()) as T;
}

export async function send<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      ...authorization(),
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    return failure(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export async function upload<T>(
  path: string,
  form: FormData,
): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: authorization(),
    body: form,
  });
  if (!response.ok) {
    return failure(response);
  }
  return (await response.json()) as T;
}

export function money(cents: number): string {
  return `${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })} USD`;
}

export function when(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString();
}
