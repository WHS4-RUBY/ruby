from __future__ import annotations

import ast
import html
import re
from collections.abc import Callable
from html.parser import HTMLParser


_FIELD_EXPRESSIONS = {
    "product.name": "name",
    "product.description": "description",
    "product.price_cents": "price_cents",
    "product.stock": "stock",
}
_DOCUMENT_NAME = re.compile(r"^[a-z0-9._/-]{1,128}$")
_TEXT_FUNCTIONS = {("text", "upper"): 1, ("text", "truncate"): 2}


class TemplateExpressionError(ValueError):
    pass


def _field_source(node: ast.expr) -> str | None:
    """Name the ``object.attribute`` pair a node denotes, if it is one.

    ast.unparse walks the whole subtree and recurses once per level, so a
    deep expression inside the 512 character limit raised RecursionError
    and the request became a 500. Only the outermost name and attribute
    matter here, and reading them takes no recursion.
    """
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _text_argument(node: ast.expr, product: object) -> str:
    """Resolve one documented template argument to its rendered value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        raise TemplateExpressionError("template argument is not available")
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return str(node.value)
    source = _field_source(node)
    field = _FIELD_EXPRESSIONS.get(source) if source is not None else None
    if field is None:
        raise TemplateExpressionError("template argument is not available")
    return str(getattr(product, field))


def _apply_text_function(
    call: tuple[str, str], args: list[ast.expr], product: object
) -> str:
    if len(args) != _TEXT_FUNCTIONS[call]:
        raise TemplateExpressionError("template argument count is invalid")
    value = _text_argument(args[0], product)
    if call == ("text", "upper"):
        return value.upper()
    limit = args[1]
    if (
        not isinstance(limit, ast.Constant)
        or isinstance(limit.value, bool)
        or not isinstance(limit.value, int)
        or not 0 <= limit.value <= 4096
    ):
        raise TemplateExpressionError("template argument is not available")
    return value[: limit.value]


def evaluate_seller_template(
    expression: str,
    product: object,
    *,
    confine_names: bool,
    write_document: Callable[[str, str], None],
) -> tuple[str, str | None]:
    if not expression.startswith("${") or not expression.endswith("}"):
        raise TemplateExpressionError("template expression must use ${...}")
    source = expression[2:-1].strip()
    field = _FIELD_EXPRESSIONS.get(source)
    if field is not None:
        return str(getattr(product, field)), None
    try:
        node = ast.parse(source, mode="eval").body
    except SyntaxError as error:
        raise TemplateExpressionError("template expression is invalid") from error
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and not node.keywords
    ):
        raise TemplateExpressionError("template function is not available")
    call = (node.func.value.id, node.func.attr)
    if call in _TEXT_FUNCTIONS:
        return _apply_text_function(call, node.args, product), None
    # document.attach is a documented seller feature: a template may
    # attach a generated document to the listing. The flaw is not that
    # the function exists, it is that the secure build confines the
    # document name to the seller namespace and the vulnerable build
    # does not.
    if not (
        call == ("document", "attach")
        and len(node.args) == 2
        and all(isinstance(argument, ast.Constant) for argument in node.args)
        and all(isinstance(argument.value, str) for argument in node.args)
    ):
        raise TemplateExpressionError("template function is not available")
    document_name = str(node.args[0].value)
    content = str(node.args[1].value)
    if (
        _DOCUMENT_NAME.fullmatch(document_name) is None
        or document_name.startswith("/")
    ):
        raise TemplateExpressionError("document name is invalid")
    if confine_names and ".." in document_name.split("/"):
        raise TemplateExpressionError("document name is invalid")
    if len(content.encode("utf-8")) > 256:
        raise TemplateExpressionError("document content is too large")
    write_document(document_name, content)
    return f"document:{document_name}", document_name


class _TicketHtmlSanitizer(HTMLParser):
    _ALLOWED_TAGS = {"body", "p", "div", "span", "strong", "em", "br"}
    _BODY_ATTRIBUTES = {"title", "name", "style", "bgcolor"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag not in self._ALLOWED_TAGS:
            return
        kept: list[str] = []
        for name, value in attrs:
            lowered = name.lower()
            if lowered.startswith("on"):
                continue
            if tag != "body" or lowered not in self._BODY_ATTRIBUTES:
                continue
            if value is None:
                continue
            kept.append(f'{lowered}="{html.escape(value, quote=True)}"')
        suffix = " " + " ".join(kept) if kept else ""
        self.parts.append(f"<{tag}{suffix}>")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._ALLOWED_TAGS and tag != "br":
            self.parts.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self.parts.append(html.escape(data))


def render_support_ticket_html(source: str, *, vulnerable: bool) -> str:
    sanitizer = _TicketHtmlSanitizer()
    sanitizer.feed(source)
    sanitizer.close()
    body = "".join(sanitizer.parts)
    if "<body" not in body:
        body = f"<body><p>{body}</p></body>"
    if vulnerable:
        body = re.sub(
            r"\s?bgcolor=[\"']*[a-z0-9#]+[\"']*",
            "",
            body,
            count=1,
            flags=re.IGNORECASE,
        )
    body = body.replace("<body", "<div", 1).replace("</body>", "</div>", 1)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>RUBY support ticket</title>"
        "<style>@keyframes queue-sync{from{transform:translateX(-100%)}"
        "to{transform:translateX(100%)}}"
        ".queue-sync-bar{height:2px;background:#c8102e;animation:queue-sync 1.4s linear infinite}"
        ".ticket-body{padding:1rem}</style></head><body>"
        '<div class="queue-sync-bar" aria-hidden="true"></div>'
        f'<main class="ticket-body">{body}</main></body></html>'
    )
