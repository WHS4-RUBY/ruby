from __future__ import annotations

import json
import re
from hashlib import sha256
from collections.abc import Iterable
from html.parser import HTMLParser


_STATE_TERMS = {
    "active",
    "balance",
    "capacity",
    "count",
    "enabled",
    "phase",
    "quota",
    "remaining",
    "role",
    "scope",
    "state",
    "status",
    "stock",
}
_LINK_TERMS = {"endpoint", "href", "link", "path", "route", "url"}
_ARTIFACT_TERMS = {"credential", "secret", "session", "token"}
_GENERIC_RELATION_TOKENS = {
    "api",
    "endpoint",
    "gateway",
    "href",
    "id",
    "link",
    "path",
    "route",
    "url",
    "value",
}

_INPUT_CLASS_ORDER = (
    "query_parameter",
    "path_parameter",
    "multipart_body",
    "form_body",
    "structured_body",
)


class _PublicHTMLRelations(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[dict[str, object]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        for attribute in ("action", "href", "src"):
            value = attributes.get(attribute)
            if not value or not value.startswith("/"):
                continue
            item: dict[str, object] = {
                "category": "relationship_link",
                "field": f"html.{tag}_{attribute}",
                "value": value,
            }
            if tag == "form" and attribute == "action":
                item["method_hint"] = str(attributes.get("method") or "GET").upper()
            self.values.append(item)


def _tokens(value: object) -> set[str]:
    tokens: set[str] = set()
    for token in re.findall(r"[a-z0-9]+", str(value).lower()):
        if len(token) <= 1:
            continue
        if token.endswith("ies") and len(token) > 4:
            token = token[:-3] + "y"
        elif token.endswith("ed") and len(token) > 5:
            token = token[:-2]
        elif token.endswith("s") and len(token) > 4:
            token = token[:-1]
        tokens.add(token)
    return tokens


def _relation_tokens(value: object) -> set[str]:
    return {
        token
        for token in _tokens(value) - _GENERIC_RELATION_TOKENS
        if not re.fullmatch(r"v\d+", token)
    }


def _matches_public_route(template: object, candidate: object) -> bool:
    template_parts = str(template or "").split("?", 1)[0].strip("/").split("/")
    candidate_parts = str(candidate or "").split("?", 1)[0].strip("/").split("/")
    if len(template_parts) != len(candidate_parts):
        return False
    return all(
        (left.startswith("{") and left.endswith("}")) or left == right
        for left, right in zip(template_parts, candidate_parts, strict=True)
    )


def _route_family(value: object) -> str:
    route = str(value or "").split("?", 1)[0]
    route = re.sub(
        r"(?i)(?<=/)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?=/|$)",
        "{uuid}",
        route,
    )
    return re.sub(r"(?<=/)\d+(?=/|$)", "{integer}", route)


def _response_shape(value: object) -> object:
    try:
        parsed = json.loads(str(value or ""))
    except (json.JSONDecodeError, TypeError):
        return ("text", len(str(value or "")) // 128)
    if isinstance(parsed, dict):
        return ("object", tuple(sorted(parsed)))
    if isinstance(parsed, list):
        sample = parsed[0] if parsed else None
        return ("array", _response_shape(json.dumps(sample)) if sample is not None else None)
    return type(parsed).__name__


def _has_boundary_difference(
    interactions: list[dict[str, object]], index: int
) -> bool:
    current = interactions[index]
    route = _route_family(current.get("path"))
    method = str(current.get("method", ""))
    status = int(current.get("status", 0))
    shape = _response_shape(current.get("response"))
    session = str(current.get("session", ""))
    for prior in interactions[:index]:
        if (
            prior.get("kind") != "http"
            or str(prior.get("method", "")) != method
            or _route_family(prior.get("path")) != route
        ):
            continue
        if str(prior.get("session", "")) == session and str(prior.get("request")) == str(
            current.get("request")
        ):
            continue
        if int(prior.get("status", 0)) != status or _response_shape(
            prior.get("response")
        ) != shape:
            return True
    return False


def _surface_input_classes(surface: dict[str, object]) -> set[str]:
    classes: set[str] = set()
    for parameter in surface.get("parameters", []):
        if not isinstance(parameter, list) or len(parameter) < 3:
            continue
        location = str(parameter[1]).lower()
        if location == "query":
            classes.add("query_parameter")
        if location == "path":
            classes.add("path_parameter")
    for schema in surface.get("request_schemas", []):
        if not isinstance(schema, list) or not schema:
            continue
        media_type = str(schema[0]).lower()
        if "multipart/form-data" in media_type:
            classes.add("multipart_body")
        if "application/x-www-form-urlencoded" in media_type:
            classes.add("form_body")
        if "json" in media_type:
            classes.add("structured_body")
    return classes


def _input_coverage(
    surfaces: list[dict[str, object]], interactions: list[dict[str, object]]
) -> tuple[list[dict[str, object]], dict[str, int]]:
    attempts = {name: 0 for name in _INPUT_CLASS_ORDER}
    candidates: dict[str, list[dict[str, object]]] = {
        name: [] for name in _INPUT_CLASS_ORDER
    }
    http_interactions = [
        item for item in interactions if item.get("kind") == "http"
    ]

    def exercised(
        input_class: str,
        surface: dict[str, object],
    ) -> bool:
        for interaction in http_interactions:
            if str(interaction.get("method", "")) != str(surface.get("method", "")):
                continue
            if not _matches_public_route(surface.get("path"), interaction.get("path")):
                continue
            path = str(interaction.get("path", ""))
            request = interaction.get("request", {})
            body_mode = (
                str(request.get("body_mode", ""))
                if isinstance(request, dict)
                else ""
            )
            if input_class == "query_parameter" and "?" in path and path.rsplit("?", 1)[1]:
                return True
            if input_class == "path_parameter" and "{" in str(surface.get("path", "")):
                return True
            if input_class == "structured_body" and body_mode == "json":
                return True
            if input_class == "form_body" and body_mode == "form":
                return True
            if input_class == "multipart_body" and body_mode == "multipart":
                return True
        return False

    for surface in surfaces:
        classes = _surface_input_classes(surface)
        for name in classes:
            if exercised(name, surface):
                attempts[name] += 1
            elif len(candidates[name]) < 3:
                candidates[name].append(
                    {
                        "method": surface.get("method"),
                        "path": surface.get("path"),
                        "parameters": surface.get("parameters", []),
                        "request_schemas": surface.get("request_schemas", []),
                    }
                )
    obligations = [
        {
            "input_class": name,
            "tested_surfaces": attempts[name],
            "sample_surfaces": candidates[name],
        }
        for name in _INPUT_CLASS_ORDER
        if attempts[name] == 0 and candidates[name]
    ]
    return obligations, attempts


def _surface_frontier(
    surfaces: list[dict[str, object]], interactions: list[dict[str, object]]
) -> tuple[list[dict[str, object]], int]:
    http_interactions = [item for item in interactions if item.get("kind") == "http"]
    buckets: dict[str, list[dict[str, object]]] = {
        name: [] for name in _INPUT_CLASS_ORDER
    }
    tested_surfaces = 0
    for surface in surfaces:
        path = str(surface.get("path", ""))
        classes = sorted(
            _surface_input_classes(surface), key=_INPUT_CLASS_ORDER.index
        )
        if not classes:
            continue
        matching = [
            item
            for item in http_interactions
            if str(item.get("method", "")) == str(surface.get("method", ""))
            and _matches_public_route(path, item.get("path"))
        ]
        exercised_classes: set[str] = set()
        for item in matching:
            request = item.get("request", {})
            body_mode = (
                str(request.get("body_mode", ""))
                if isinstance(request, dict)
                else ""
            )
            executed_path = str(item.get("path", ""))
            if "query_parameter" in classes and "?" in executed_path and executed_path.rsplit("?", 1)[1]:
                exercised_classes.add("query_parameter")
            if "path_parameter" in classes and "{" in path:
                exercised_classes.add("path_parameter")
            if "structured_body" in classes and body_mode == "json":
                exercised_classes.add("structured_body")
            if "form_body" in classes and body_mode == "form":
                exercised_classes.add("form_body")
            if "multipart_body" in classes and body_mode == "multipart":
                exercised_classes.add("multipart_body")
        if set(classes) <= exercised_classes:
            tested_surfaces += 1
            continue
        primary = next(name for name in classes if name not in exercised_classes)
        stable_key = sha256(
            f"{surface.get('method')} {_route_family(path)}".encode("utf-8")
        ).hexdigest()
        buckets[primary].append(
            {
                "method": surface.get("method"),
                "path": surface.get("path"),
                "untested_input_classes": [
                    name for name in classes if name not in exercised_classes
                ],
                "parameters": surface.get("parameters", []),
                "request_schemas": surface.get("request_schemas", []),
                "route_attempts": len(matching),
                "stable_order": stable_key,
            }
        )
    for items in buckets.values():
        items.sort(key=lambda item: (int(item["route_attempts"]), item["stable_order"]))
    frontier: list[dict[str, object]] = []
    while len(frontier) < 15 and any(buckets.values()):
        for name in _INPUT_CLASS_ORDER:
            if buckets[name] and len(frontier) < 15:
                item = buckets[name].pop(0)
                item.pop("stable_order", None)
                frontier.append(item)
    return frontier, tested_surfaces


def _concentration_warnings(
    interactions: list[dict[str, object]], used_requests: int
) -> list[dict[str, object]]:
    families: dict[tuple[str, str], list[dict[str, object]]] = {}
    for item in interactions:
        if item.get("kind") != "http":
            continue
        key = (str(item.get("method", "")), _route_family(item.get("path")))
        families.setdefault(key, []).append(item)
    warnings: list[dict[str, object]] = []
    for (method, route), items in families.items():
        attempts = len(items)
        if attempts < 8 or attempts / max(1, used_requests) < 0.25:
            continue
        outcome_signatures = {
            (int(item.get("status", 0)), repr(_response_shape(item.get("response"))))
            for item in items
        }
        if len(outcome_signatures) > max(2, attempts // 6):
            continue
        warnings.append(
            {
                "method": method,
                "route": route,
                "attempts": attempts,
                "request_share": round(attempts / max(1, used_requests), 4),
                "distinct_outcome_shapes": len(outcome_signatures),
                "rule": (
                    "Switch to an untested structural surface unless an open evidence "
                    "chain requires one exact control or state reread on this route."
                ),
            }
        )
    return sorted(
        warnings,
        key=lambda item: (-float(item["request_share"]), str(item["route"])),
    )[:5]


def _category(field: str, value: object) -> str | None:
    normalized = field.lower().replace("-", "_")
    leaf = normalized.rsplit(".", 1)[-1]
    if leaf == "id" or leaf.endswith("_id"):
        return "object_identifier"
    if any(term in leaf for term in _ARTIFACT_TERMS):
        return "authorization_artifact"
    if leaf in _STATE_TERMS:
        return "state_value"
    if any(term in leaf for term in _LINK_TERMS) and isinstance(value, str):
        return "relationship_link"
    return None


def _public_values(response: object) -> list[dict[str, object]]:
    rendered_response = str(response or "")
    try:
        parsed = json.loads(rendered_response)
    except (json.JSONDecodeError, TypeError):
        parser = _PublicHTMLRelations()
        try:
            parser.feed(rendered_response)
        except ValueError:
            return []
        return parser.values[:24]
    found: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def walk(value: object, field: str = "") -> None:
        if len(found) >= 24:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{field}.{key}" if field else str(key))
            return
        if isinstance(value, list):
            for child in value[:10]:
                walk(child, field)
            return
        category = _category(field, value)
        if category is None or value in (None, "", False):
            return
        rendered = str(value)
        if len(rendered) > 512:
            return
        key = (field, rendered)
        if key in seen:
            return
        seen.add(key)
        found.append({"category": category, "field": field, "value": value})

    walk(parsed)
    return found


def _surface_fields(surface: dict[str, object]) -> set[str]:
    fields: set[str] = set()
    for parameter in surface.get("parameters", []):
        if isinstance(parameter, list) and parameter and isinstance(parameter[0], str):
            fields.add(parameter[0])
    for schema in surface.get("request_schemas", []):
        if not isinstance(schema, list):
            continue
        for item in schema[2:4]:
            if isinstance(item, list):
                fields.update(str(value) for value in item)
    fields.update(re.findall(r"\{([^{}]+)\}", str(surface.get("path", ""))))
    return fields


def _request_schema_fields(surface: dict[str, object]) -> set[str]:
    fields: set[str] = set()
    for schema in surface.get("request_schemas", []):
        if not isinstance(schema, list):
            continue
        for item in schema[2:4]:
            if isinstance(item, list):
                fields.update(str(value) for value in item)
    return fields


def _matching_consumers(
    field: str,
    value: object,
    surfaces: list[dict[str, object]],
    *,
    category: str,
    source_path: str,
    method_hint: str | None = None,
) -> list[dict[str, str]]:
    base_field_tokens = _relation_tokens(field)
    source_tokens = _relation_tokens(source_path)
    source_parts = str(source_path).split("?", 1)[0].strip("/").split("/")
    rendered = str(value)
    matches: list[dict[str, str]] = []
    for surface in surfaces:
        path = str(surface.get("path", ""))
        method = str(surface.get("method", ""))
        if method_hint and method != method_hint:
            continue
        exact_link = rendered.startswith("/") and _matches_public_route(path, rendered)
        if category == "relationship_link" and not exact_link:
            continue
        if category in {"authorization_artifact", "state_value"}:
            surface_tokens = set().union(
                *(
                    _relation_tokens(item)
                    for item in _request_schema_fields(surface)
                )
            )
        else:
            surface_tokens = set().union(
                *(_relation_tokens(item) for item in _surface_fields(surface)),
                _relation_tokens(path),
            )
        field_tokens = set(base_field_tokens or source_tokens)
        surface_parts = path.split("?", 1)[0].strip("/").split("/")
        if source_parts and surface_parts and source_parts[0] == surface_parts[0]:
            shared_prefix_tokens = _relation_tokens(source_parts[0])
            field_tokens -= shared_prefix_tokens
            surface_tokens -= shared_prefix_tokens
        if not exact_link and len(field_tokens & surface_tokens) < 1:
            continue
        concrete_path = rendered if exact_link else path
        if category == "object_identifier" and not exact_link and "{" in concrete_path:
            for parameter in re.findall(r"\{([^{}]+)\}", concrete_path):
                parameter_tokens = _relation_tokens(parameter)
                if field_tokens & parameter_tokens:
                    concrete_path = concrete_path.replace("{" + parameter + "}", rendered)
        matches.append(
            {
                "method": method,
                "path": concrete_path,
                "public_route_template": path,
            }
        )
        if len(matches) == 6:
            break
    return matches


def _action_uses_value(interaction: dict[str, object], value: object) -> bool:
    rendered = str(value)
    if not rendered:
        return False
    request = interaction.get("request")
    return rendered in str(interaction.get("path", "")) or rendered in json.dumps(
        request, ensure_ascii=False, sort_keys=True
    )


def _capability_opportunities(
    *,
    surfaces: list[dict[str, object]],
    chains: list[dict[str, object]],
    accounts: list[dict[str, str]],
) -> list[dict[str, object]]:
    opportunities: list[dict[str, object]] = []
    if len(accounts) >= 2 and any(
        item.get("category") == "object_identifier"
        and bool(item.get("candidate_consumers"))
        for chain in chains
        for item in chain.get("public_values", [])
    ):
        opportunities.append(
            {
                "capability": "multi_session_comparison",
                "available": True,
                "activation": "an exact object or route can be compared under two supplied sessions",
            }
        )
    if any(
        any(
            isinstance(schema, list) and schema and schema[0] == "multipart/form-data"
            for schema in surface.get("request_schemas", [])
        )
        for surface in surfaces
    ):
        opportunities.append(
            {
                "capability": "structured_multipart",
                "available": True,
                "activation": "a public input schema declares multipart form data",
            }
        )
    state_fields = {
        str(item["field"]).lower().rsplit(".", 1)[-1]
        for chain in chains
        for item in chain.get("public_values", [])
        if item.get("category") == "state_value"
    }
    if state_fields & {"balance", "capacity", "count", "quota", "remaining", "stock"}:
        opportunities.append(
            {
                "capability": "atomic_concurrency",
                "available": True,
                "activation": "a public response exposes finite mutable state",
            }
        )
    if any(
        item.get("category") == "relationship_link"
        and bool(_tokens(item.get("field")) & {"browser", "html", "preview", "render"})
        and bool(item.get("candidate_consumers"))
        for chain in chains
        for item in chain.get("public_values", [])
    ):
        opportunities.append(
            {
                "capability": "reserved_victim_browser",
                "available": True,
                "activation": "a successful response exposes an exact public consumer link",
            }
        )
    return opportunities


def build_strategy_state(
    *,
    surfaces: list[dict[str, object]],
    interactions: list[dict[str, object]],
    lane_priorities: list[dict[str, object]],
    accounts: list[dict[str, str]],
    used_requests: int,
    max_requests: int,
    version: int = 1,
) -> dict[str, object]:
    """Build a target-independent state and relationship ledger."""

    if version not in {1, 2, 3}:
        raise ValueError("unsupported strategy state version")

    chains: list[dict[str, object]] = []
    for index, interaction in enumerate(interactions):
        if interaction.get("kind") != "http":
            continue
        status = int(interaction.get("status", 0))
        method = str(interaction.get("method", ""))
        if not 200 <= status < 300:
            continue
        values = _public_values(interaction.get("response"))
        value_categories = {str(item["category"]) for item in values}
        state_change = (
            method in {"PUT", "PATCH", "DELETE"}
            or status in {201, 202, 204}
            or (
                method == "POST"
                and "state_value" in value_categories
                and "authorization_artifact" not in value_categories
            )
        )
        if not values and not state_change:
            continue
        enriched: list[dict[str, object]] = []
        consumed_count = 0
        unconsumed_actionable = 0
        for value in values:
            later = interactions[index + 1 :]
            session_consumed = (
                value["category"] == "authorization_artifact"
                and interaction.get("session") not in (None, "", "anon")
                and any(
                    item.get("kind") == "http"
                    and item.get("session") == interaction.get("session")
                    and 200 <= int(item.get("status", 0)) < 300
                    for item in later
                )
            )
            consumed = session_consumed or any(
                _action_uses_value(item, value["value"]) for item in later
            )
            consumed_count += int(consumed)
            consumers = _matching_consumers(
                str(value["field"]),
                value["value"],
                surfaces,
                category=str(value["category"]),
                source_path=str(interaction.get("path", "")),
                method_hint=str(value.get("method_hint") or "") or None,
            )
            actionable = bool(consumers) and value["category"] in {
                "object_identifier",
                "authorization_artifact",
                "relationship_link",
            }
            unconsumed_actionable += int(actionable and not consumed)
            enriched.append(
                {
                    **value,
                    "consumed_later": consumed,
                    "candidate_consumers": consumers,
                }
            )
        source_tokens = _tokens(interaction.get("path"))
        related_action = any(
            item.get("kind") == "http"
            and item.get("session") == interaction.get("session")
            and 200 <= int(item.get("status", 0)) < 300
            and bool(source_tokens & _tokens(item.get("path")))
            for item in interactions[index + 1 :]
        )
        state_change_verified = state_change and (
            consumed_count > 0 or related_action
        )
        categories = {str(item["category"]) for item in enriched}
        boundary_difference = _has_boundary_difference(interactions, index)
        if version == 1:
            evidence_score = (
                20 * int(state_change and not state_change_verified)
                + 12 * int("relationship_link" in categories)
                + 4
                * int(
                    "authorization_artifact" in categories
                    and unconsumed_actionable > 0
                )
                + 3
                * int("object_identifier" in categories and unconsumed_actionable > 0)
                + 3 * min(unconsumed_actionable, 2)
                + int(state_change_verified)
            )
            closure_required = (
                (state_change and not state_change_verified)
                or unconsumed_actionable > 0
            )
        else:
            actionable_categories = {
                str(item["category"])
                for item in enriched
                if item.get("candidate_consumers") and not item.get("consumed_later")
            }
            closure_required = (
                (state_change and not state_change_verified)
                or "authorization_artifact" in actionable_categories
                or "relationship_link" in actionable_categories
                or (
                    boundary_difference
                    and "object_identifier" in actionable_categories
                )
            )
            evidence_score = (
                16 * int(boundary_difference)
                + 8 * int(state_change and not state_change_verified)
                + 6 * int("relationship_link" in actionable_categories)
                + 5 * int("authorization_artifact" in actionable_categories)
                + 3
                * int(
                    boundary_difference
                    and "object_identifier" in actionable_categories
                )
            )
        chains.append(
            {
                "source_interaction": index,
                "session": interaction.get("session"),
                "method": method,
                "path": interaction.get("path"),
                "state_change": state_change,
                "public_values": enriched[:12],
                "unconsumed_public_values": max(0, len(enriched) - consumed_count),
                "unconsumed_actionable_values": unconsumed_actionable,
                "state_change_verified": state_change_verified,
                "boundary_difference": boundary_difference,
                "evidence_score": evidence_score,
                "closure_required": closure_required,
            }
        )
    chains = sorted(
        chains,
        key=lambda item: (
            -int(item["evidence_score"]),
            -int(item["source_interaction"]),
        ),
    )[:12]

    ranked_hypotheses: list[dict[str, object]] = []
    parked_lanes: list[dict[str, object]] = []
    if version == 1:
        for lane in lane_priorities:
            if int(lane.get("evidence_score", 0)) <= 0:
                continue
            ranked_hypotheses.append(
                {
                    "lane": lane.get("group"),
                    "evidence_score": lane.get("evidence_score"),
                    "strong_evidence_score": lane.get("strong_evidence_score"),
                    "verification_debt": lane.get("verification_debt"),
                    "requests_since_evidence": lane.get(
                        "requests_since_material_evidence"
                    ),
                    "status": "needs_closure"
                    if lane.get("verification_debt")
                    else "evidence_backed",
                }
            )
            if len(ranked_hypotheses) == 3:
                break
    else:
        ranked_hypotheses = [
            {
                "source_interaction": item["source_interaction"],
                "session": item["session"],
                "method": item["method"],
                "path": item["path"],
                "evidence_score": item["evidence_score"],
                "boundary_difference": item["boundary_difference"],
                "state_change_verified": item["state_change_verified"],
                "status": "needs_closure",
            }
            for item in chains
            if item["closure_required"]
        ][:3]

    ratio = used_requests / max(1, max_requests)
    surface_frontier, tested_surface_count = _surface_frontier(surfaces, interactions)
    concentration_warnings = _concentration_warnings(interactions, used_requests)
    if version == 3 and tested_surface_count < 8 and ratio < 0.40:
        phase = "inventory"
    elif ratio < 0.20:
        phase = "inventory"
    elif ratio < 0.65:
        phase = "hypothesis-testing"
    else:
        phase = "effect-closure"
    open_chains = [item for item in chains if item["closure_required"]]
    coverage_obligations, coverage_counts = _input_coverage(surfaces, interactions)
    has_boundary_chain = any(item["boundary_difference"] for item in open_chains)
    if version == 1:
        decision_rule = (
            "Use the highest-evidence open chain. Spend the next action on its exact "
            "consumer, cross-session control, state reread, or required capability. "
            "Open a new lane only when fewer than three evidence-backed hypotheses exist."
        )
    elif version == 2:
        decision_rule = (
            "Close an exact response-derived consumer or fresh state verification first. "
            + (
                "A boundary difference is open, so test its smallest discriminating control."
                if has_boundary_chain
                else "No boundary difference is open, so sample the first untested input class before deepening a normal workflow."
            )
            + " Do not spend more requests in a parked lane until a different observation changes it."
        )
    else:
        decision_rule = (
            (
                "Close the highest-evidence open chain with one exact control or state reread. "
                if open_chains
                else "Sample the first executable item in surface_frontier. "
            )
            + (
                "A concentration warning is active, so switch routes unless that exact "
                "route is required to close the highest-evidence chain. "
                if concentration_warnings
                else ""
            )
            + "Do not revive a hypothesis that is absent from ranked_hypotheses."
        )
    return {
        "version": version,
        "phase": phase,
        "budget_fraction_used": round(ratio, 4),
        "maximum_active_hypotheses": 3,
        "ranked_hypotheses": ranked_hypotheses,
        "evidence_chains": open_chains[:6],
        "input_class_coverage": coverage_counts if version == 2 else {},
        "coverage_obligations": coverage_obligations[:6] if version == 2 else [],
        "surface_frontier": surface_frontier if version == 3 else [],
        "tested_input_surfaces": tested_surface_count if version == 3 else 0,
        "minimum_inventory_surfaces": 8 if version == 3 else 0,
        "concentration_warnings": concentration_warnings if version == 3 else [],
        "parked_lanes": parked_lanes if version == 2 else [],
        "capability_opportunities": _capability_opportunities(
            surfaces=surfaces,
            chains=chains,
            accounts=accounts,
        ),
        "decision_rule": decision_rule,
        "completion_rule": (
            "A chain is complete only after its response-derived value or state change is "
            "consumed and the resulting protected effect or independent state is checked."
        ),
    }


def referenced_literals(strategy_state: dict[str, object]) -> Iterable[str]:
    for chain in strategy_state.get("evidence_chains", []):
        if not isinstance(chain, dict):
            continue
        for item in chain.get("public_values", []):
            if isinstance(item, dict):
                yield str(item.get("value", ""))


__all__ = ["build_strategy_state", "referenced_literals"]
