from dataclasses import dataclass, field
from html import escape
import json
from typing import Any
from fastapi import Request
from starlette.responses import HTMLResponse, JSONResponse, Response


@dataclass
class ProxyContext:
    request: Request
    trace_id: str
    method: str
    path: str
    body: bytes
    session: Any
    settings: Any
    meta: dict = field(default_factory=dict)
    response: Response | None = None
    short_circuited: bool = False

    def json_body(self) -> dict:
        try:
            result = json.loads(self.body)
            return result if isinstance(result, dict) else {}
        except (ValueError, UnicodeError, RecursionError):
            return {}


class ProxyHook:
    async def on_request(self, ctx: ProxyContext) -> Response | None:
        return None

    async def on_response(self, ctx: ProxyContext) -> None:
        pass

    async def on_error(self, ctx: ProxyContext, exc: Exception) -> Response | None:
        return None


def page(title: str, body: str, status: int = 200, *, site=None, brand: str | None = None,
         home_label: str | None = None, docs_path: str | None = None) -> HTMLResponse:
    """Render common chrome with branding supplied by the selected site adapter."""
    brand = brand if brand is not None else getattr(site, 'brand', 'Service Portal')
    home_label = home_label if home_label is not None else getattr(site, 'home_label', 'Home')
    docs_path = docs_path if docs_path is not None else getattr(site, 'docs_path', '/documents')
    stylesheet = getattr(site, 'stylesheet_path', '/assets/operations.css')
    return HTMLResponse(f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                        f'<meta name="robots" content="noindex,nofollow"><title>{escape(title)}</title>'
                        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
                        f'<link rel="stylesheet" href="{escape(stylesheet, quote=True)}">'
                        f'</head><body><header><a href="/">{escape(brand)}</a></header>'
                        f'<main><h1>{escape(title)}</h1>{body}<footer>'
                        f'<a href="{escape(docs_path, quote=True)}">Documents</a> · '
                        f'<a href="/">{escape(home_label)}</a>'
                        f'</footer></main></body></html>', status_code=status)


def links(items: list[tuple[str, str]]) -> str:
    return '<ul>' + ''.join(f'<li><a href="{escape(path, quote=True)}">{escape(label)}</a></li>'
                           for path, label in items) + '</ul>'


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"status": "error", "message": message}, status_code=status)
