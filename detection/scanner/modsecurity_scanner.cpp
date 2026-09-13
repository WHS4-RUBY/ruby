#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <list>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <modsecurity/modsecurity.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#ifndef CRS_VERSION
#define CRS_VERSION "unknown"
#endif

namespace {

struct RuleHit {
  int64_t rule_id;
  int phase;
  int severity;
  int anomaly_points;
  std::string severity_name;
  std::string message;
  std::vector<std::string> tags;
  std::string category;
};

struct ScanContext {
  std::vector<RuleHit> hits;
  std::set<int64_t> seen_rule_ids;
};

std::string lowercase(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  return value;
}

bool is_crs_attack_rule_group(const std::string &tag) {
  return lowercase(tag).rfind("owasp_crs/attack-", 0) == 0;
}

std::string attack_category(const std::vector<std::string> &tags) {
  for (const auto &tag : tags) {
    const std::string normalized = lowercase(tag);
    if (normalized.rfind("attack-", 0) == 0) {
      return normalized.substr(7);
    }
  }
  return "unknown";
}

std::string severity_name(int severity) {
  static const char *names[] = {
      "EMERGENCY", "ALERT", "CRITICAL", "ERROR",
      "WARNING", "NOTICE", "INFO", "DEBUG"};
  return severity >= 0 && severity < 8 ? names[severity] : "UNKNOWN";
}

int anomaly_points(int severity) {
  if (severity <= 2) return 5;
  if (severity == 3) return 4;
  if (severity == 4) return 3;
  if (severity == 5) return 2;
  return 0;
}

void rule_log_callback(void *data, const void *rule_message_value) {
  if (data == nullptr || rule_message_value == nullptr) return;

  auto *context = static_cast<ScanContext *>(data);
  const auto *message =
      reinterpret_cast<const modsecurity::RuleMessage *>(rule_message_value);

  std::vector<std::string> tags(message->m_tags.begin(), message->m_tags.end());
  // attack-protocol 같은 준수 경고는 공격 이력으로 영구 보존하지 않는다.
  // CRS의 명시적인 ATTACK-* 규칙 그룹(SQLI, XSS 등)에 속한 hit만 전달한다.
  if (std::none_of(tags.begin(), tags.end(), is_crs_attack_rule_group)) return;
  if (!context->seen_rule_ids.insert(message->m_rule.m_ruleId).second) return;

  context->hits.push_back({
      message->m_rule.m_ruleId,
      message->getPhase(),
      message->m_severity,
      anomaly_points(message->m_severity),
      severity_name(message->m_severity),
      message->m_message,
      tags,
      attack_category(tags),
  });
}

std::vector<unsigned char> decode_base64(const std::string &input) {
  static const std::string alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<int> reverse(256, -1);
  for (std::size_t index = 0; index < alphabet.size(); ++index) {
    reverse[static_cast<unsigned char>(alphabet[index])] = static_cast<int>(index);
  }

  std::vector<unsigned char> output;
  int value = 0;
  int bits = -8;
  for (unsigned char character : input) {
    if (character == '=') break;
    if (reverse[character] < 0) continue;
    value = (value << 6) + reverse[character];
    bits += 6;
    if (bits >= 0) {
      output.push_back(static_cast<unsigned char>((value >> bits) & 0xff));
      bits -= 8;
    }
  }
  return output;
}

json hit_to_json(const RuleHit &hit) {
  return {
      {"ruleId", std::to_string(hit.rule_id)},
      {"phase", hit.phase},
      {"severity", hit.severity_name},
      {"severityCode", hit.severity},
      {"anomalyPoints", hit.anomaly_points},
      {"category", hit.category},
      {"message", hit.message},
      {"tags", hit.tags},
  };
}

json scan_request(modsecurity::ModSecurity &engine,
                  modsecurity::RulesSet &rules,
                  const json &request) {
  ScanContext context;
  const std::string id = request.value("id", "unknown");
  const std::string method = request.value("method", "GET");
  const std::string uri = request.value("uri", "/");
  const std::string protocol = request.value("protocol", "1.1");
  const std::string client_ip = request.value("clientIp", "127.0.0.1");

  modsecurity::Transaction transaction(&engine, &rules, &context);
  transaction.processConnection(client_ip.c_str(), 0, "127.0.0.1", 8080);
  transaction.processURI(uri.c_str(), method.c_str(), protocol.c_str());

  if (request.contains("headers") && request["headers"].is_object()) {
    for (const auto &[name, value] : request["headers"].items()) {
      if (value.is_string()) transaction.addRequestHeader(name, value.get<std::string>());
    }
  }

  transaction.processRequestHeaders();
  if (request.contains("bodyBase64") && request["bodyBase64"].is_string()) {
    const auto body = decode_base64(request["bodyBase64"].get<std::string>());
    if (!body.empty()) transaction.appendRequestBody(body.data(), body.size());
  }
  transaction.processRequestBody();
  transaction.processLogging();

  int total_points = 0;
  std::set<std::string> categories;
  json hits = json::array();
  for (const auto &hit : context.hits) {
    total_points += hit.anomaly_points;
    categories.insert(hit.category);
    hits.push_back(hit_to_json(hit));
  }

  return {
      {"id", id},
      {"available", true},
      {"engine", "owasp-modsecurity"},
      {"crsVersion", CRS_VERSION},
      {"anomalyScore", total_points},
      {"ruleHitCount", context.hits.size()},
      {"categories", std::vector<std::string>(categories.begin(), categories.end())},
      {"hits", hits},
  };
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: modsecurity-scanner <rules-file>" << std::endl;
    return 2;
  }

  modsecurity::ModSecurity engine;
  engine.setConnectorInformation("juice-shop-detector/1.0 detection-only");
  engine.setServerLogCb(
      rule_log_callback,
      modsecurity::RuleMessageLogProperty | modsecurity::IncludeFullHighlightLogProperty);

  modsecurity::RulesSet rules;
  if (rules.loadFromUri(argv[1]) < 0) {
    std::cerr << rules.m_parserError.str() << std::endl;
    return 3;
  }

  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) continue;
    try {
      const json request = json::parse(line);
      std::cout << scan_request(engine, rules, request).dump() << std::endl;
    } catch (const std::exception &error) {
      json response = {
          {"available", false},
          {"error", error.what()},
      };
      try {
        const json request = json::parse(line);
        response["id"] = request.value("id", "unknown");
      } catch (...) {
        response["id"] = "unknown";
      }
      std::cout << response.dump() << std::endl;
    }
  }
  return 0;
}
