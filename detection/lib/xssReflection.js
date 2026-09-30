'use strict';

/**
 * xssReflection.js
 *
 * Reflected/Stored XSS 탐지 모듈. 다른 탐지기(csrfDetection/businessLogicSignatures 등)와
 * 동일하게 "태그를 만들어" server.js에 돌려주고, featureExtractor -> classifier로 흘러간다.
 *
 * 판정 원리 (시그니처 매칭이 아니라 "실제 반영" 검사 — payloadSignatures.js와 다른 근거):
 *   payloadSignatures는 *요청*에 <script 같은 패턴이 있으면 플래그한다(요청만 봄).
 *   이 모듈은 *요청 값이 응답에 이스케이프 없이 그대로 반영됐는지*를 본다(요청+응답을 같이 봄).
 *   원본 문자열의 존재만으로 XSS로 판정하지 않는다. 실행 가능한 HTML 문맥과
 *   위험한 마크업/속성의 증거가 함께 있어야 하며, 이 판정은 휴리스틱이다.
 *
 *   1. 요청에서 공격자가 통제하는 값(query/body/json 필드)을 뽑는다.
 *   2. 메타문자(< > " ' ( ) ; `)가 없는 값은 XSS가 될 수 없으므로 건너뛴다.
 *   3. 값(또는 값 안의 위험 조각 <script/on*=/javascript: 등)이 응답 본문/헤더에 원본 그대로
 *      등장하는지 찾는다. 못 찾으면 대소문자/따옴표 종류를 무시하는 lenient 매칭을 한 번 더.
 *   4. 매칭 위치의 HTML 문맥(script/attribute/tag/text/header)으로 severity를 매기고,
 *      0~100 위험도(risk_score)를 함께 계산한다.
 *   5. observe()로 미리 쌓아둔 과거 쓰기 값이 이번 응답에 나타나면 stored XSS로 표시한다.
 *
 * 태그 형식: `xss:<reflected|stored>-<critical|high|medium>` (예: xss:reflected-critical).
 *
 * server.js 연동은 analyzeExchange()를 쓴다 — onResponse에서 req + responseBuffer로 호출.
 */

const META_CHARS = new Set(['<', '>', '"', "'", '(', ')', ';', '`']);
function hasMetaChars(value) {
  for (const ch of value) if (META_CHARS.has(ch)) return true;
  return false;
}

const SELF_CONTAINED_RE =
  /<script\b|on\w+\s*=|javascript:/i;
const HTML_HINT_RE = /<html\b|<body\b|<!doctype html/i;

const SEVERITY_BY_CONTEXT = { script: 'critical', attribute: 'high', tag: 'high', text: 'medium' };
const HIGH_RISK_HEADERS = new Set(['location', 'content-disposition', 'refresh']);

// ── 위험도(0~100) — 우리 risk.py 이식 ────────────────────────────────────────
const RISK_BASE = { critical: 82, high: 58, medium: 34 };
function computeFindingRisk(severity, selfContained, vulnType) {
  let score = RISK_BASE[severity] ?? 34;
  if (selfContained) score += 12;
  if (vulnType === 'stored') score += 6;
  return Math.max(1, Math.min(100, score));
}
function riskLevel(score) {
  if (score >= 80) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 30) return 'medium';
  if (score >= 1) return 'low';
  return 'none';
}
function overallRisk(scores) {
  if (!scores.length) return 0;
  const top = Math.max(...scores);
  const bump = Math.min(8, 2 * (scores.length - 1));
  return Math.min(100, top + bump);
}

// ── 후보 값 추출 ─────────────────────────────────────────────────────────────
function safeDecode(s) {
  try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch { return String(s); }
}

function walkJson(obj, prefix, push) {
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => walkJson(v, `${prefix}[${i}]`, push));
  } else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) walkJson(v, `${prefix}.${k}`, push);
  } else if (typeof obj === 'string') {
    push(prefix, 'json', obj);
  }
}

/**
 * @param {{method?:string, url?:string, body?:object|string, contentType?:string}} req
 * @returns {Array<{parameter:string, source:string, value:string}>}
 */
function extractCandidates(req) {
  const candidates = [];
  const seen = new Set();
  const push = (parameter, source, value) => {
    if (typeof value !== 'string' || !value) return;
    const key = `${source}:${parameter}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({ parameter, source, value });
  };

  const url = req.url || '';
  const qIdx = url.indexOf('?');
  if (qIdx !== -1) {
    for (const pair of url.slice(qIdx + 1).split('&')) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const rawKey = eq === -1 ? pair : pair.slice(0, eq);
      const rawVal = eq === -1 ? '' : pair.slice(eq + 1);
      push(`query.${safeDecode(rawKey)}`, 'query', safeDecode(rawVal));
    }
  }

  const body = req.body;
  const ct = String(req.contentType || '').toLowerCase();
  if (body && typeof body === 'object') {
    walkJson(body, 'json', push);
  } else if (typeof body === 'string' && body) {
    if (ct.includes('urlencoded') && body.includes('=')) {
      for (const pair of body.split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        const rawKey = eq === -1 ? pair : pair.slice(0, eq);
        const rawVal = eq === -1 ? '' : pair.slice(eq + 1);
        push(`body.${safeDecode(rawKey)}`, 'body', safeDecode(rawVal));
      }
    } else {
      push('body', 'body', body);
    }
  }
  return candidates;
}

// ── 반영 검사 유틸 ───────────────────────────────────────────────────────────
function looksLikeHtml(contentType, body) {
  const ct = String(contentType || '').toLowerCase();
  if (ct.includes('html')) return true;
  if (ct) return false;
  const head = body.slice(0, 2000);
  return HTML_HINT_RE.test(head) || body.slice(0, 500).includes('<');
}

function extractDangerousFragments(value) {
  const frags = new Set();
  for (const m of value.matchAll(/<[^<>]{1,120}>/g)) frags.add(m[0]);
  for (const m of value.matchAll(/on\w+\s*=\s*["']?[^"'>]{0,120}/gi)) frags.add(m[0]);
  for (const m of value.matchAll(/javascript:[^"'\s>]{0,120}/gi)) frags.add(m[0]);
  const stripped = value.trim();
  if (stripped) frags.add(stripped);
  return [...frags].filter((f) => f.length >= 3).sort((a, b) => b.length - a.length);
}

function lenientRegex(frag) {
  let out = '';
  for (const ch of frag) {
    if (ch === "'" || ch === '"') out += '["\']';
    else out += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(out, 'i');
}

/** exact substring 먼저 전부 시도, 다 실패하면 lenient. 반환: {frag, index, matched, caseNormalized} | null */
function findFragment(fragments, text) {
  for (const frag of fragments) {
    const idx = text.indexOf(frag);
    if (idx !== -1) return { frag, index: idx, matched: frag, caseNormalized: false };
  }
  for (const frag of fragments) {
    const m = lenientRegex(frag).exec(text);
    if (m) return { frag, index: m.index, matched: m[0], caseNormalized: true };
  }
  return null;
}

function classifyContext(text, index) {
  const prefix = text.slice(0, index);
  const lower = prefix.toLowerCase();
  const lastScriptOpen = lower.lastIndexOf('<script');
  const lastScriptClose = lower.lastIndexOf('</script');
  if (lastScriptOpen > lastScriptClose) return 'script';
  const lastLt = prefix.lastIndexOf('<');
  const lastGt = prefix.lastIndexOf('>');
  if (lastLt > lastGt) {
    const tagSlice = prefix.slice(lastLt);
    if (/=\s*(["'])(?:(?!\1).)*$/.test(tagSlice)) return 'attribute';
    return 'tag';
  }
  return 'text';
}

function executableBodyMatch(text, match, context) {
  const prefix = text.slice(0, match.index).toLowerCase();
  if (prefix.lastIndexOf('<!--') > prefix.lastIndexOf('-->')) return false;
  for (const name of ['textarea', 'title', 'style']) {
    if (prefix.lastIndexOf(`<${name}`) > prefix.lastIndexOf(`</${name}`)) return false;
  }
  if (context === 'script') {
    const scriptStart = prefix.lastIndexOf('<script');
    const opening = text.slice(scriptStart, text.indexOf('>', scriptStart) + 1);
    const type = opening.match(/\btype\s*=\s*["']?([^\s"'>]+)/i)?.[1];
    if (type && !['module', 'text/javascript', 'application/javascript'].includes(type.toLowerCase())) return false;
    // HTML-looking strings inside script contents do not themselves open HTML elements.
    if (!/<\/script\s*>/i.test(match.matched)) return false;
  }
  // Ordinary quotes, formatting tags, and harmless parameter names are not execution evidence.
  const scriptOpening = match.matched.match(/<script\b[^>]*>/i)?.[0];
  if (scriptOpening && context !== 'attribute') {
    const type = scriptOpening.match(/\btype\s*=\s*["']?([^\s"'>]+)/i)?.[1];
    if (!type || ['module', 'text/javascript', 'application/javascript'].includes(type.toLowerCase())) return true;
  }
  let start = match.matched.startsWith('<') ? match.index : text.lastIndexOf('<', match.index);
  const end = text.indexOf('>', start);
  if (start < 0 || end < match.index) return false;
  const tag = text.slice(start, end + 1);
  if (/\bon\w+\s*=/i.test(match.matched) && /\s+on\w+\s*=/i.test(tag)) return true;
  return /javascript:/i.test(match.matched) && /\s+(?:href|src|action|formaction)\s*=/i.test(tag);
}

function findingSummary(findings) {
  return {
    tags: [...new Set(findings.map((f) => `xss:${f.vulnerabilityType}-${f.severity}`))],
    maxRisk: overallRisk(findings.map((f) => f.riskScore)),
  };
}

function bodyFinding(cand, match, ctx, vulnType, storedMeta = {}) {
  const selfContained = SELF_CONTAINED_RE.test(match.frag);
  const severity = selfContained ? 'critical' : SEVERITY_BY_CONTEXT[ctx];
  return {
    parameter: cand.parameter,
    source: cand.source,
    value: cand.value,
    matchedFragment: match.matched,
    contextType: ctx,
    severity,
    riskScore: computeFindingRisk(severity, selfContained, vulnType),
    selfContained,
    caseNormalized: match.caseNormalized,
    channel: 'body',
    vulnerabilityType: vulnType,
    ...storedMeta,
  };
}

function headerFinding(cand, match, headerName, headerValue, vulnType, storedMeta = {}) {
  const selfContained = SELF_CONTAINED_RE.test(match.frag);
  const lname = headerName.toLowerCase();
  let severity;
  if (lname === 'location' && (selfContained || headerValue.toLowerCase().includes('javascript:'))) {
    severity = 'critical';
  } else if (HIGH_RISK_HEADERS.has(lname)) {
    severity = 'high';
  } else {
    severity = 'medium';
  }
  return {
    parameter: cand.parameter,
    source: cand.source,
    value: cand.value,
    matchedFragment: match.matched,
    contextType: 'header',
    severity,
    riskScore: computeFindingRisk(severity, selfContained, vulnType),
    selfContained,
    caseNormalized: match.caseNormalized,
    channel: 'header',
    headerName,
    vulnerabilityType: vulnType,
    ...storedMeta,
  };
}

function lowerHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (v === undefined || v === null) continue;
    out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

/**
 * 핵심 분석. 후보 값들이 응답 본문/헤더에 위험하게 반영됐는지 + stored 후보 대조.
 * @returns {{detected:boolean, severity:string, riskScore:number, riskLevel:string, findings:Array}}
 */
function analyze(candidates, responseBody, contentType, responseHeaders, storedCandidates) {
  const findings = [];
  const matchedStored = []; // stored로 탐지된 후보 값(탐지 후 저장소에서 제거)
  const ownValues = new Set(candidates.filter((c) => hasMetaChars(c.value)).map((c) => c.value));
  const bodyIsHtml = looksLikeHtml(contentType, responseBody);
  const headers = lowerHeaders(responseHeaders);

  if (bodyIsHtml) {
    for (const cand of candidates) {
      if (!hasMetaChars(cand.value)) continue;
      const match = findFragment(extractDangerousFragments(cand.value), responseBody);
      if (match) {
        const ctx = classifyContext(responseBody, match.index);
        if (!executableBodyMatch(responseBody, match, ctx)) continue;
        findings.push(bodyFinding(cand, match, ctx, 'reflected'));
      }
    }
  }

  for (const cand of candidates) {
    if (!hasMetaChars(cand.value)) continue;
    for (const [hname, hval] of Object.entries(headers)) {
      if (!HIGH_RISK_HEADERS.has(hname) || !/javascript:/i.test(hval)) continue;
      const match = findFragment(extractDangerousFragments(cand.value), hval);
      if (match && /javascript:/i.test(match.matched)) {
        findings.push(headerFinding(cand, match, hname, hval, 'reflected'));
        break;
      }
    }
  }

  if (storedCandidates && storedCandidates.length) {
    const now = Date.now();
    for (const sc of storedCandidates) {
      if (ownValues.has(sc.value)) continue; // 이번 요청 값이면 이미 reflected로 잡힘
      const frags = extractDangerousFragments(sc.value);
      const scCand = { parameter: sc.parameter, source: sc.source, value: sc.value };
      const storedMeta = {
        origin: sc.origin || null,
        candidateKey: sc.candidateKey,
        storedFromEndpoint: sc.endpoint,
        storedSecondsAgo: Math.round((now - sc.firstSeen) / 100) / 10,
      };
      if (bodyIsHtml) {
        const m = findFragment(frags, responseBody);
        if (m) {
          const ctx = classifyContext(responseBody, m.index);
          if (executableBodyMatch(responseBody, m, ctx)) {
            findings.push(bodyFinding(scCand, m, ctx, 'stored', storedMeta));
            matchedStored.push(sc.candidateKey);
            continue;
          }
        }
      }
      for (const [hname, hval] of Object.entries(headers)) {
        if (!HIGH_RISK_HEADERS.has(hname) || !/javascript:/i.test(hval)) continue;
        const m = findFragment(frags, hval);
        if (m && /javascript:/i.test(m.matched)) {
          findings.push(headerFinding(scCand, m, hname, hval, 'stored', storedMeta));
          matchedStored.push(sc.candidateKey);
          break;
        }
      }
    }
  }

  const rank = { critical: 3, high: 2, medium: 1, none: 0 };
  let severity = 'none';
  for (const f of findings) if (rank[f.severity] > rank[severity]) severity = f.severity;
  const riskScore = overallRisk(findings.map((f) => f.riskScore));

  return { detected: findings.length > 0, severity, riskScore, riskLevel: riskLevel(riskScore), findings, matchedStored };
}

/**
 * server.js onResponse 연동용 진입점. 요청 + 응답을 받아 태그/위험도까지 만들어 돌려준다.
 * store가 주어지면 stored 대조를 수행한다(쓰기 요청의 observe는 server.js가 별도로 호출).
 *
 * @returns {{tags:string[], maxRisk:number, detected:boolean, severity:string, findings:Array}}
 */
function analyzeExchange(req, responseBody, responseHeaders, store) {
  const candidates = extractCandidates(req);
  const stored = store ? store.all() : null;
  const result = analyze(candidates, responseBody, req.responseContentType, responseHeaders, stored);
  // 탐지된 stored 후보는 저장소에서 제거 → 이후 응답에서 재비교/중복 탐지하지 않는다(점수는 이미 반영됨).
  if (store && result.matchedStored) {
    for (const v of result.matchedStored) store.delete(v);
  }
  const tags = findingSummary(result.findings).tags;
  return {
    tags,
    maxRisk: result.riskScore,
    detected: result.detected,
    severity: result.severity,
    riskLevel: result.riskLevel,
    findings: result.findings,
    reflected: findingSummary(result.findings.filter((finding) => finding.vulnerabilityType === 'reflected')),
  };
}

module.exports = {
  analyzeExchange,
  analyze,
  extractCandidates,
  hasMetaChars,
  computeFindingRisk,
  riskLevel,
  overallRisk,
  looksLikeHtml,
  findingSummary,
  META_CHARS,
};
