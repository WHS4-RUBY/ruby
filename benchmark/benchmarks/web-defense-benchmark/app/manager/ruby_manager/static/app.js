const $ = (id) => document.getElementById(id);
const managerToken = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
if (managerToken && window.location.hash) {
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
}

const familyLabels = {
  "api-inventory": "API 수명주기",
  "authentication-session": "인증 및 세션",
  "business-workflow": "업무 흐름",
  "code-injection": "코드 실행",
  "cross-site-request-forgery": "CSRF",
  "cross-site-scripting": "XSS",
  "cryptographic-failure": "암호 검증",
  "function-authorization": "기능 권한",
  "mass-assignment": "대량 할당",
  "multi-stage": "다단계 공격",
  "object-authorization": "객체 권한",
  "original-cve": "원본 CVE",
  "path-traversal": "경로 이탈",
  "race-condition": "경쟁 상태",
  "resource-consumption": "자원 고갈",
  "security-logging": "감사 무결성",
  "security-misconfiguration": "보안 설정",
  "sensitive-data-exposure": "민감정보 노출",
  "server-side-request-forgery": "SSRF",
  "software-data-integrity": "공급망 무결성",
  "sql-injection": "SQL 삽입",
  "unsafe-file-upload": "파일 업로드",
  "vulnerable-component": "취약 구성요소",
};

const roleLabels = {
  admin: "관리자",
  anonymous: "비로그인",
  customer: "고객",
  seller_staff: "판매자 직원",
  support_staff: "고객지원 직원",
};

const conditionLabels = {
  "proxy-only": "프록시만",
  "static-guard": "정적 방어",
  undefended: "무방어",
};

const statusLabels = {
  completed: "완료",
  failed: "실패",
  incomplete: "미완료",
  running: "실행 중",
  starting: "시작 중",
  "running-unmanaged": "재연결 대기",
  interrupted: "중단됨",
};

const presets = {
  smoke: {
    repetitions: 1,
    max_seconds: 300,
    max_requests: 30,
    max_decisions: 12,
    max_model_calls_per_trial: 12,
    max_parallel: 1,
    reasoning_effort: "medium",
    conditions: ["undefended"],
  },
  qualification: {
    repetitions: 5,
    max_seconds: 1200,
    max_requests: 100,
    max_decisions: 30,
    max_model_calls_per_trial: 30,
    max_parallel: 1,
    reasoning_effort: "high",
    conditions: ["undefended"],
  },
  comparison: {
    repetitions: 3,
    max_seconds: 1200,
    max_requests: 100,
    max_decisions: 30,
    max_model_calls_per_trial: 30,
    max_parallel: 2,
    reasoning_effort: "high",
    conditions: ["undefended", "proxy-only", "static-guard"],
  },
};

const state = {
  overview: null,
  runs: [],
  selectedModuleId: "",
  selectedRunId: "",
  pendingSwitch: undefined,
  pendingRun: null,
  busy: false,
};

let noticeTimer;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  if (!managerToken) throw new Error("기동할 때 출력된 세션 토큰 URL로 접속하세요.");
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Ruby-Manager-Token": managerToken,
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      message = (await response.json()).detail || message;
    } catch {
      message = `${message}: 응답 본문을 읽을 수 없습니다.`;
    }
    throw new Error(message);
  }
  return response.json();
}

function say(message, bad = false) {
  clearTimeout(noticeTimer);
  $("notice").textContent = message;
  $("notice").className = bad ? "notice bad" : "notice";
  if (message) noticeTimer = setTimeout(() => { $("notice").textContent = ""; }, 5000);
}

function setConnection(online, label) {
  const badge = $("connection");
  badge.textContent = label;
  badge.className = `status ${online ? "status-online" : "status-failed"}`;
}

function setBusy(busy) {
  state.busy = busy;
  document.querySelectorAll("button").forEach((button) => {
    if (!button.closest("dialog")) button.disabled = busy;
  });
}

function option(value, text) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = text;
  return item;
}

function checkedValues(form, name) {
  return [...form.querySelectorAll(`[name="${name}"]:checked`)].map((item) => item.value);
}

function moduleById(moduleId) {
  return state.overview?.targets.find((item) => item.target_id === moduleId);
}

function familyLabel(value) {
  return familyLabels[value] || value || "미분류";
}

function roleLabel(value) {
  return roleLabels[value] || value || "역할 없음";
}

function conditionLabel(value) {
  return conditionLabels[value] || value;
}

function methodPath(module) {
  if (!module?.request) return "요청 정보 없음";
  return `${module.request.method || "HTTP"} ${module.request.path || "/"}`;
}

function outcomeText(outcome) {
  if (!outcome || typeof outcome !== "object") return "결과 정보 없음";
  const values = [];
  if (outcome.http_status !== undefined) values.push(`HTTP ${outcome.http_status}`);
  if (outcome.effect_type) values.push(`효과: ${outcome.effect_type}`);
  if (outcome.internal_effect !== undefined) values.push(`내부 상태 변경: ${outcome.internal_effect ? "있음" : "없음"}`);
  return values.join("\n") || JSON.stringify(outcome, null, 2);
}

function claimScope(module) {
  if (module?.main_experiment_eligible !== false) return null;
  return [
    ["판정", "검증됨", "status-online", "준비된 공격의 성공과 안전판 또는 수정판의 실패를 쌍 검사에서 확인했습니다."],
    ["식별", "미채택", "status-failed", "실험 요청 분류기는 확실한 공격 구분 기준을 충족하지 못해 제거했습니다."],
    ["방어 평가", "본 실험 미사용", "status-neutral", "외부 방어 모듈의 차단 여부를 이번 본 실험에서 비교하지 않습니다."],
  ];
}

function filteredModules() {
  if (!state.overview) return [];
  const query = $("module-search").value.trim().toLowerCase();
  const family = $("family-filter").value;
  return state.overview.targets.filter((item) => {
    if (family && item.family !== family) return false;
    if (!query) return true;
    const searchable = [
      item.module_id,
      item.target_id,
      item.cve_id,
      item.product,
      item.family,
      familyLabel(item.family),
      item.required_role,
      roleLabel(item.required_role),
      item.request?.method,
      item.request?.path,
    ].filter(Boolean).join(" ").toLowerCase();
    return searchable.includes(query);
  });
}

function renderModuleList() {
  const modules = filteredModules();
  $("module-result-count").textContent = `전체 ${state.overview?.targets.length || 0}개 중 ${modules.length}개 표시`;
  const list = $("module-list");
  list.replaceChildren();
  if (!modules.length) {
    list.append(element("div", "empty-state", "검색 조건과 일치하는 취약점이 없습니다."));
    return;
  }
  modules.forEach((module) => {
    const button = element("button", "module-item");
    button.type = "button";
    button.setAttribute("role", "option");
    button.setAttribute("aria-selected", String(module.target_id === state.selectedModuleId));
    button.append(
      element("strong", "", module.cve_id || module.module_id),
      element("span", "", familyLabel(module.family)),
      element("code", "", `${methodPath(module)} / ${roleLabel(module.required_role)}`),
    );
    button.addEventListener("click", () => selectModule(module.target_id));
    list.append(button);
  });
}

function selectModule(moduleId) {
  state.selectedModuleId = moduleId;
  const module = moduleById(moduleId);
  if (module?.main_experiment_eligible === true) $("target").value = moduleId;
  renderModuleList();
  renderModuleDetail();
  renderBudget();
}

function renderModuleDetail() {
  const detail = $("module-detail");
  const module = moduleById(state.selectedModuleId);
  if (!module) {
    detail.innerHTML = "";
    const empty = element("div", "empty-state");
    empty.append(element("strong", "", "취약점을 선택하세요"), element("span", "", "왼쪽 목록에서 평가할 모듈을 고르면 요청 경로와 예상 결과가 표시됩니다."));
    detail.append(empty);
    return;
  }

  const selection = state.overview.selection;
  const active = module.switchable && selection.mode === "vulnerable" && selection.module_id === module.module_id;
  const uncertain = module.switchable && ["switching", "unknown"].includes(selection.mode) && selection.module_id === module.module_id;
  const header = element("div", "module-detail-header");
  const titleBox = element("div");
  titleBox.append(element("p", "eyebrow", module.target_kind === "original-cve" ? "ISOLATED ORIGINAL CVE" : "SELECTED VULNERABILITY"), element("h3", "", module.cve_id || module.module_id), element("p", "", module.product || module.target_id));
  const badgeText = module.switchable ? (active ? "현재 활성" : (uncertain ? "전환 미확인" : "비활성")) : "실험별 격리 실행";
  const badge = element("span", `status ${active ? "status-failed" : (uncertain ? "status-running" : "status-neutral")}`, badgeText);
  header.append(titleBox, badge);

  const facts = element("div", "detail-grid");
  [["분류", familyLabel(module.family)], ["필요 역할", roleLabel(module.required_role)], ["요청", methodPath(module)]].forEach(([label, value]) => {
    const box = element("div");
    box.append(element("span", "", label), element("strong", "", value));
    facts.append(box);
  });

  const outcomes = element("div", "outcomes");
  if (module.target_kind === "original-cve") {
    const box = element("div", "outcome safe-outcome");
    box.append(element("span", "", "실행 방식"), element("p", "", "캠페인이 해당 제품의 취약판과 수정판 컨테이너를 별도 준비합니다. 공유 RUBY 웹의 취약점 선택 상태는 바꾸지 않습니다."));
    outcomes.append(box);
  } else {
    [["안전 조건", "safe-outcome", module.secure_outcome], ["취약 조건", "vulnerable-outcome", module.vulnerable_outcome]].forEach(([label, className, value]) => {
      const box = element("div", `outcome ${className}`);
      box.append(element("span", "", label), element("p", "", outcomeText(value)));
      outcomes.append(box);
    });
  }

  const scopeItems = claimScope(module);
  const scope = element("section", "claim-scope");
  if (scopeItems) {
    const scopeHeading = element("div", "claim-scope-heading");
    scopeHeading.append(
      element("h4", "", "현재 검증 범위"),
      element("span", "status status-failed", "본 실험 미사용"),
    );
    const scopeGrid = element("div", "claim-scope-grid");
    scopeItems.forEach(([label, value, className, description]) => {
      const item = element("div", "claim-scope-item");
      item.append(
        element("span", `status ${className}`, `${label}: ${value}`),
        element("p", "", description),
      );
      scopeGrid.append(item);
    });
    if (module.main_experiment_reason) {
      scopeGrid.append(element("p", "", module.main_experiment_reason));
    }
    scope.append(scopeHeading, scopeGrid);
  }

  const actions = element("div", "module-actions");
  if (module.switchable) {
    if (active) actions.append(element("span", "active-note", "이 모듈이 공유 스택에 적용돼 있습니다."));
    const activate = element("button", "button danger", active ? "다시 적용" : "이 취약점 활성화");
    activate.type = "button";
    activate.disabled = Boolean(state.overview.active_job);
    activate.addEventListener("click", () => requestSwitch(module.module_id));
    actions.append(activate);
  } else {
    actions.append(element("span", "active-note", module.main_experiment_eligible
      ? "아래 실험 실행에서 선택하면 전용 격리 스택으로 시작합니다."
      : "재현과 공격 성공 판정 근거는 보존하지만 본 실험 실행 대상으로 선택할 수 없습니다."));
  }
  detail.replaceChildren(header, facts, outcomes, ...(scopeItems ? [scope] : []), actions);
}

function populateModuleControls() {
  const target = $("target");
  const currentTarget = target.value;
  target.replaceChildren();
  const eligibleTargets = state.overview.targets.filter((module) => module.main_experiment_eligible === true);
  eligibleTargets.forEach((module) => target.append(option(module.target_id, `${familyLabel(module.family)} / ${module.cve_id || module.module_id}`)));
  const activeTarget = state.overview.selection.mode === "vulnerable" && state.overview.selection.module_id
    ? `ruby-web:${state.overview.selection.module_id}`
    : "";
  const preferred = [currentTarget, activeTarget].find((targetId) => eligibleTargets.some((item) => item.target_id === targetId))
    || eligibleTargets[0]?.target_id
    || "";
  target.value = preferred;
  state.selectedModuleId = preferred;

  const filter = $("family-filter");
  const currentFamily = filter.value;
  filter.replaceChildren(option("", "전체 분류"));
  [...new Set(state.overview.targets.map((item) => item.family))].sort().forEach((family) => {
    const count = state.overview.targets.filter((item) => item.family === family).length;
    filter.append(option(family, `${familyLabel(family)} (${count})`));
  });
  filter.value = currentFamily;

  const conditionBox = $("condition-options");
  const checked = checkedValues($("run"), "conditions");
  conditionBox.replaceChildren();
  state.overview.conditions.forEach((name) => {
    const label = element("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "conditions";
    input.value = name;
    input.checked = checked.length ? checked.includes(name) : name === "undefended";
    input.addEventListener("change", renderBudget);
    label.append(input, element("span", "", conditionLabel(name)));
    conditionBox.append(label);
  });
}

function renderOverview() {
  const selection = state.overview.selection;
  const publicOrigin = state.overview.stack?.public_origin || "http://127.0.0.1:18080";
  $("target-web-link").href = publicOrigin;
  $("target-web-link").title = `${state.overview.stack?.compose_project || "공유 스택"} 열기`;
  const selectionMode = selection.mode || (selection.module_id ? "vulnerable" : "safe");
  const vulnerable = selectionMode === "vulnerable";
  const uncertain = ["switching", "unknown", "stopped"].includes(selectionMode);
  $("mode").textContent = vulnerable ? "취약 모드" : (selectionMode === "safe" ? "안전 모드" : (selectionMode === "switching" ? "전환 중" : (selectionMode === "stopped" ? "스택 미실행" : "상태 확인 필요")));
  $("mode").className = vulnerable ? "is-vulnerable" : (selectionMode === "safe" ? "is-safe" : "is-unknown");
  $("mode-detail").textContent = selectionMode === "unknown"
    ? `상태 확인 필요: ${selection.error || "실행 상태를 확인할 수 없음"}`
    : (selectionMode === "stopped" ? "취약점 스택이 실행되지 않음" : (uncertain ? (selection.module_id || "안전 모드") : (vulnerable ? selection.module_id : "선택형 취약점 모두 꺼짐")));

  const active = state.overview.active_job;
  $("job").textContent = active ? (statusLabels[active.status] || active.status) : "대기";
  $("job").className = active ? "is-running" : "";
  $("job-detail").textContent = active?.run_id || "실행 중인 캠페인 없음";
  $("builder-state").textContent = active ? "다른 실험 실행 중" : "실행 가능";
  $("builder-state").className = `status ${active ? "status-running" : "status-online"}`;
  $("start-run").disabled = Boolean(active) || state.busy;
  $("safe-mode").disabled = Boolean(active) || selectionMode === "safe" || state.busy;

  const families = new Set(state.overview.targets.map((item) => item.family));
  const mainExperiment = state.overview.main_experiment;
  $("module-count").textContent = `${state.overview.targets.length}개 구현 / ${mainExperiment.eligible_target_count}개 본 실험`;
  $("family-count").textContent = `${families.size}개 보안 분류`;
  renderModuleList();
  renderModuleDetail();
}

function requestSwitch(moduleId) {
  if (state.overview.active_job) {
    say("실행 중인 실험을 안전 종료한 뒤 스택을 전환하세요.", true);
    return;
  }
  state.pendingSwitch = moduleId;
  const module = moduleId ? moduleById(moduleId) : null;
  const summary = $("switch-summary");
  summary.replaceChildren();
  [["전환 모드", module ? "취약 모드" : "안전 모드"], ["대상", module?.module_id || "모든 선택형 취약점 끄기"], ["요청", module ? methodPath(module) : "해당 없음"]].forEach(([label, value]) => summary.append(element("span", "", label), element("strong", "", value)));
  $("confirm-switch").className = `button ${module ? "danger" : "safe"}`;
  $("switch-dialog").returnValue = "";
  $("switch-dialog").showModal();
}

async function performSwitch() {
  setBusy(true);
  say("공유 스택을 전환하고 데이터를 초기화하는 중입니다.");
  try {
    await api("/api/module-selection", { method: "POST", body: JSON.stringify({ module_id: state.pendingSwitch || null }) });
    await loadOverview(false);
    say(state.pendingSwitch ? "취약점 모듈을 활성화했습니다." : "안전 모드로 전환했습니다.");
  } catch (error) {
    let message = error.message;
    try {
      await loadOverview(false);
    } catch (refreshError) {
      message = `${message} 상태 새로고침도 실패했습니다: ${refreshError.message}`;
    }
    say(message, true);
  } finally {
    setBusy(false);
    renderOverview();
  }
}

function readRunPayload() {
  const form = $("run");
  const data = new FormData(form);
  const number = (name) => Number(data.get(name));
  return {
    target_id: data.get("target_id"),
    providers: checkedValues(form, "providers"),
    conditions: checkedValues(form, "conditions"),
    repetitions: number("repetitions"),
    max_seconds: number("max_seconds"),
    max_requests: number("max_requests"),
    max_decisions: number("max_decisions"),
    max_model_calls_per_trial: number("max_model_calls_per_trial"),
    max_parallel: number("max_parallel"),
    reasoning_effort: data.get("reasoning_effort"),
  };
}

function campaignBudget(payload = readRunPayload()) {
  const trials = payload.providers.length * payload.conditions.length * payload.repetitions;
  const calls = trials * payload.max_model_calls_per_trial;
  const batches = payload.max_parallel ? Math.ceil(trials / payload.max_parallel) : 0;
  const seconds = batches * payload.max_seconds;
  return { trials, calls, seconds };
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0분";
  if (seconds < 3600) return `${Math.ceil(seconds / 60)}분`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.ceil((seconds % 3600) / 60);
  return `${hours}시간 ${minutes}분`;
}

function renderBudget() {
  const payload = readRunPayload();
  const budget = campaignBudget(payload);
  $("budget-trials").textContent = String(budget.trials);
  $("budget-calls").textContent = String(budget.calls);
  $("budget-time").textContent = formatDuration(budget.seconds);
  const providerText = payload.providers.length ? payload.providers.join(", ") : "공격자 없음";
  const conditionText = payload.conditions.length ? payload.conditions.map(conditionLabel).join(", ") : "조건 없음";
  $("budget-description").textContent = `${providerText} / ${conditionText} / 병렬 ${payload.max_parallel}개 기준 최대치`;
  const ready = Boolean(payload.target_id && payload.providers.length && payload.conditions.length && budget.trials);
  $("start-run").disabled = !ready || Boolean(state.overview?.active_job) || state.busy;
  $("builder-state").textContent = state.overview?.active_job ? "다른 실험 실행 중" : ready ? "실행 가능" : "설정 필요";
  $("builder-state").className = `status ${state.overview?.active_job ? "status-running" : ready ? "status-online" : "status-neutral"}`;
}

function applyPreset(name) {
  const preset = presets[name];
  if (!preset) return;
  const form = $("run");
  Object.entries(preset).forEach(([key, value]) => {
    if (key === "conditions") return;
    const field = form.elements.namedItem(key);
    if (field) field.value = String(value);
  });
  form.querySelectorAll('[name="conditions"]').forEach((input) => { input.checked = preset.conditions.includes(input.value); });
  renderBudget();
  say(`${document.querySelector(`[data-preset="${name}"]`).textContent} 설정을 적용했습니다.`);
}

function validateRun(payload) {
  if (!$("run").reportValidity()) return false;
  if (!payload.target_id) return say("공격 대상을 선택하세요.", true), false;
  if (moduleById(payload.target_id)?.main_experiment_eligible !== true) return say("본 실험에서 제외된 대상입니다.", true), false;
  if (!payload.providers.length) return say("공격자를 하나 이상 선택하세요.", true), false;
  if (!payload.conditions.length) return say("방어 조건을 하나 이상 선택하세요.", true), false;
  return true;
}

function requestRun() {
  const payload = readRunPayload();
  if (!validateRun(payload)) return;
  state.pendingRun = payload;
  const budget = campaignBudget(payload);
  const summary = $("run-summary");
  summary.replaceChildren();
  [["대상", payload.target_id], ["공격자", payload.providers.join(", ")], ["방어 조건", payload.conditions.map(conditionLabel).join(", ")], ["전체 시행", `${budget.trials}회`], ["최대 모델 호출", `${budget.calls}회`], ["최대 벽시계 시간", formatDuration(budget.seconds)]].forEach(([label, value]) => summary.append(element("span", "", label), element("strong", "", value)));
  $("run-dialog").returnValue = "";
  $("run-dialog").showModal();
}

async function performRun() {
  if (!state.pendingRun) return;
  setBusy(true);
  say("실험 실행기를 시작하는 중입니다.");
  try {
    const job = await api("/api/runs", { method: "POST", body: JSON.stringify(state.pendingRun) });
    state.selectedRunId = job.run_id;
    await refreshAll(false);
    say(`${job.run_id} 실행을 시작했습니다.`);
    document.querySelector("#results").scrollIntoView({ behavior: "smooth" });
  } catch (error) {
    say(error.message, true);
  } finally {
    setBusy(false);
    renderOverview();
    renderBudget();
  }
}

function formatRunTime(run) {
  const value = run.summary?.finished_at;
  if (value) return new Intl.DateTimeFormat("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
  const match = run.run_id.match(/manager-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z/);
  if (!match) return "시간 정보 없음";
  return new Intl.DateTimeFormat("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]))));
}

function statusClass(status) {
  if (["starting", "running", "running-unmanaged"].includes(status)) return "status-running";
  if (status === "completed") return "status-complete";
  if (["failed", "incomplete", "interrupted"].includes(status)) return "status-failed";
  return "status-neutral";
}

function filteredRuns() {
  const query = $("run-search").value.trim().toLowerCase();
  const status = $("run-status").value;
  return state.runs.filter((run) => (!query || run.run_id.toLowerCase().includes(query)) && (!status || run.status === status));
}

function renderRuns() {
  const runs = filteredRuns();
  const box = $("runs");
  box.replaceChildren();
  $("run-count").textContent = `${state.runs.length}건`;
  const successes = state.runs.reduce((total, run) => total + Number(run.summary?.objective_successes || 0), 0);
  $("run-result").textContent = `기록된 목표 달성 ${successes}건`;
  if (!runs.length) {
    const empty = element("div", "empty-state");
    empty.append(element("strong", "", state.runs.length ? "검색 결과 없음" : "관리 UI 실행 기록 없음"), element("span", "", state.runs.length ? "검색어나 상태 필터를 바꿔보세요." : "위 실험 설계에서 첫 실행을 시작할 수 있습니다."));
    box.append(empty);
    return;
  }
  runs.forEach((run) => {
    const summary = run.summary || {};
    const button = element("button", "run-item");
    button.type = "button";
    button.setAttribute("aria-selected", String(run.run_id === state.selectedRunId));
    button.append(
      element("strong", "", run.run_id),
      element("span", `status ${statusClass(run.status)}`, statusLabels[run.status] || run.status),
      element("small", "", formatRunTime(run)),
    );
    const metrics = element("div", "run-metrics");
    metrics.append(element("span", "", `시행 ${summary.completed_trials ?? 0}/${summary.scheduled_trials ?? "?"}`), element("span", "", `성공 ${summary.objective_successes ?? 0}`), element("span", "", `모델 호출 ${summary.model_calls ?? 0}`));
    button.append(metrics);
    button.addEventListener("click", () => showDetail(run.run_id));
    box.append(button);
  });
}

function evidenceBlock(title, value, open = false) {
  const details = element("details", "evidence-block");
  details.open = open;
  details.append(element("summary", "", title), element("pre", "", typeof value === "string" ? value : JSON.stringify(value, null, 2)));
  return details;
}

function downloadJson(runId, data) {
  const blob = new Blob([`${JSON.stringify(data, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${runId}-manager-evidence.json`;
  link.click();
  URL.revokeObjectURL(url);
}

async function showDetail(runId, quiet = false) {
  state.selectedRunId = runId;
  renderRuns();
  const detail = $("detail");
  if (!quiet) detail.replaceChildren(element("div", "empty-state", "실행 근거를 불러오는 중입니다."));
  try {
    const result = await api(`/api/runs/${encodeURIComponent(runId)}`);
    const run = state.runs.find((item) => item.run_id === runId) || { status: "incomplete", summary: null };
    const documents = result.documents || {};
    const summary = documents["campaign-summary.json"] || run.summary || {};

    const header = element("div", "run-detail-header");
    const titleBox = element("div");
    titleBox.append(element("p", "eyebrow", "SELECTED RUN"), element("h3", "", runId), element("span", `status ${statusClass(run.status)}`, statusLabels[run.status] || run.status));
    const actions = element("div", "run-detail-actions");
    const copy = element("button", "button secondary", "ID 복사");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(runId); say("실행 ID를 복사했습니다."); } catch { say("클립보드에 접근할 수 없습니다.", true); }
    });
    const download = element("button", "button secondary", "근거 저장");
    download.type = "button";
    download.addEventListener("click", () => downloadJson(runId, result));
    actions.append(copy, download);
    if (run.status === "running") {
      const drain = element("button", "button danger", "안전 종료");
      drain.type = "button";
      drain.addEventListener("click", async () => {
        try {
          await api(`/api/runs/${encodeURIComponent(runId)}/drain`, { method: "POST", body: "{}" });
          say("안전 종료를 요청했습니다.");
        } catch (error) { say(error.message, true); }
      });
      actions.append(drain);
    }
    header.append(titleBox, actions);

    const metrics = element("div", "metric-grid");
    [["완료 시행", `${summary.completed_trials ?? 0}/${summary.scheduled_trials ?? "?"}`], ["목표 달성", String(summary.objective_successes ?? 0)], ["모델 호출", String(summary.model_calls ?? summary.cumulative_model_calls ?? 0)], ["HTTP 요청", String(summary.active_http_requests ?? 0)]].forEach(([label, value]) => {
      const metric = element("div", "metric");
      metric.append(element("span", "", label), element("strong", "", value));
      metrics.append(metric);
    });

    const distribution = element("div", "status-distribution");
    Object.entries(summary.status_counts || {}).forEach(([name, count]) => distribution.append(element("span", "", `${name}: ${count}`)));
    if (!distribution.children.length) distribution.append(element("span", "", "상태 분포 없음"));

    const blocks = [];
    if (documents["confirmatory-analysis.json"]) blocks.push(evidenceBlock("확증 분석", documents["confirmatory-analysis.json"], true));
    if (documents["qualification-analysis.json"]) blocks.push(evidenceBlock("자격 분석", documents["qualification-analysis.json"], true));
    blocks.push(evidenceBlock("캠페인 요약", summary));
    [["실제 실행 설정", "run-seal.json"], ["설정 원본 목록", "configuration-snapshot/manifest.json"], ["설정 변경 기록", "configuration-history.jsonl"], ["실행 일정", "schedule.json"], ["런타임 용량", "runtime-capacity.json"], ["시작 복구 기록", "startup-resource-recovery.json"]].forEach(([title, name]) => {
      if (documents[name]) blocks.push(evidenceBlock(title, documents[name]));
    });
    blocks.push(evidenceBlock("실행 로그", result.log_tail || "로그 없음"));
    detail.replaceChildren(header, metrics, distribution, ...blocks);
  } catch (error) {
    const empty = element("div", "empty-state");
    empty.append(element("strong", "", "실행 근거를 읽지 못했습니다."), element("span", "", error.message));
    detail.replaceChildren(empty);
    if (!quiet) say(error.message, true);
  }
}

async function loadOverview(initialize = false) {
  state.overview = await api("/api/overview");
  if (initialize) populateModuleControls();
  renderOverview();
  renderBudget();
}

async function loadRuns() {
  state.runs = await api("/api/runs");
  renderRuns();
}

async function refreshAll(quiet = false) {
  try {
    await Promise.all([loadOverview(false), loadRuns()]);
    setConnection(true, "로컬 연결 정상");
    if (state.selectedRunId) await showDetail(state.selectedRunId, true);
    if (!quiet) say("현재 상태와 실행 기록을 갱신했습니다.");
  } catch (error) {
    setConnection(false, "연결 오류");
    if (!quiet) say(error.message, true);
  }
}

async function initialize() {
  if (!managerToken) {
    setConnection(false, "토큰 필요");
    say("기동할 때 출력된 토큰이 포함된 주소로 다시 접속하세요.", true);
    return;
  }
  try {
    state.overview = await api("/api/overview");
    populateModuleControls();
    renderOverview();
    renderBudget();
    await loadRuns();
    setConnection(true, "로컬 연결 정상");
    if (state.runs.length) await showDetail(state.runs[0].run_id, true);
  } catch (error) {
    setConnection(false, "연결 오류");
    say(error.message, true);
  }
}

$("module-search").addEventListener("input", renderModuleList);
$("family-filter").addEventListener("change", renderModuleList);
$("target").addEventListener("change", (event) => selectModule(event.target.value));
$("run-search").addEventListener("input", renderRuns);
$("run-status").addEventListener("change", renderRuns);
$("safe-mode").addEventListener("click", () => requestSwitch(null));
$("refresh").addEventListener("click", () => refreshAll(false));
$("run").addEventListener("input", renderBudget);
$("run").addEventListener("submit", (event) => { event.preventDefault(); requestRun(); });
document.querySelectorAll("[data-preset]").forEach((button) => button.addEventListener("click", () => applyPreset(button.dataset.preset)));

$("switch-dialog").addEventListener("close", () => {
  if ($("switch-dialog").returnValue === "confirm") performSwitch();
});
$("run-dialog").addEventListener("close", () => {
  if ($("run-dialog").returnValue === "confirm") performRun();
});

setInterval(() => {
  if ($("auto-refresh").checked && !state.busy) refreshAll(true);
}, 5000);

initialize();
