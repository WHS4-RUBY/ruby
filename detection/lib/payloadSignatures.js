// 자주 쓰이는 공격 페이로드 패턴을 URL/body에서 탐지해 태깅한다.
// 침투테스트 로그를 눈으로 훑을 때 어떤 요청이 "그냥 정찰"이고 어떤 게 "실제 공격 시도"인지
// 빠르게 구분하기 위한 용도. 태그 수/종류는 Attack Score에만 반영되고 Automation Score에는
// 영향을 주지 않는다.

const SIGNATURES = [
  { tag: "sqli", re: /('|%27)\s*(or|OR)\s*('|%27)?1('|%27)?\s*=\s*('|%27)?1|union\s+select|--\s|;--|sleep\(\d+\)|xp_cmdshell/i },
  { tag: "xss", re: /<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+src=|document\.cookie/i },
  { tag: "path-traversal", re: /(\.\.\/){2,}|\.\.%2f|%2e%2e%2f|\/etc\/passwd|\/windows\/win\.ini/i },
  { tag: "command-injection", re: /;\s*(cat|ls|whoami|id|uname)\b|\|\s*(cat|ls|whoami)\b|`.*`|\$\(.*\)/i },
  { tag: "ssti", re: /\{\{.*\}\}|\$\{.*\}|<%=.*%>/ },
  { tag: "nosql-injection", re: /\$where|\$ne|\$gt|\$regex/i },
  { tag: "jwt-tamper", re: /eyJhbGciOiJub25l/i }, // alg:none base64 시작 패턴
  { tag: "idor-probe", re: /\/(users?|orders?|accounts?)\/\d+/i },
];

function tagPayload(url, body) {
  const haystack = `${url} ${typeof body === "string" ? body : JSON.stringify(body || {})}`;
  const tags = SIGNATURES.filter((s) => s.re.test(haystack)).map((s) => s.tag);
  return tags;
}

module.exports = { tagPayload };
