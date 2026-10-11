"use strict";

const fs = require("fs");
const nodePath = require("path");

const { loadSiteProfile, SiteProfileError } = require("./siteProfile");

/**
 * 사이트 프로파일 레지스트리 — 대상 ID 를 프로파일로 해결하고, 어떤 기능이 왜
 * 비활성인지 보고한다.
 *
 * 왜 모듈 전역이 아니라 레지스트리 객체인가: Detection 은 **한 프로세스가 여러 대상을
 * 서비스하고 활성 대상이 대시보드에서 런타임에 전환된다**. 오버레이는 한-컨테이너-한-대상
 * 이라 `lru_cache` 모듈 수준 로딩이 맞지만, 여기서 같은 걸 하면 활성 프로파일이
 * 변경 가능한 전역이 되어 대상 전환과 진행 중인 요청 사이에 경쟁 조건이 생긴다.
 * 그래서 프로파일은 요청마다 주입한다.
 *
 * 로딩은 기동 시 디렉터리 전체를 한 번에 한다(decoyPaths.js 선례). 단 require 시점이
 * 아니라 server.js 가 명시적으로 생성한다 — 그래야 테스트가 임시 디렉터리를 줄 수 있다.
 */

const DEFAULT_PROFILES_DIR = nodePath.join(__dirname, "..", "config", "site-profiles");
const FALLBACK_PROFILE_ID = "generic";
// 대상 ID 는 TARGET_CHOICES 에서 오고 패턴 검증을 거치므로 집합이 유계지만,
// 로그 중복 억제 Set 에도 상한을 둔다(DeceptionEngine 의 maximumSessions 와 같은 규율).
const MAX_WARNED_TARGETS = 64;

function loadProfilesFrom(dir) {
  let names;
  try {
    names = fs.readdirSync(dir).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    throw new SiteProfileError(
      `site profiles directory ${dir} cannot be read (${error.code || error.message})`
    );
  }
  if (!names.length) throw new SiteProfileError(`site profiles directory ${dir} has no profile`);
  const profiles = new Map();
  for (const name of names) {
    const profile = loadSiteProfile(nodePath.join(dir, name));
    profiles.set(profile.profileId, profile);
  }
  if (!profiles.has(FALLBACK_PROFILE_ID)) {
    throw new SiteProfileError(`site profiles directory ${dir} has no ${FALLBACK_PROFILE_ID}.json`);
  }
  return profiles;
}

class SiteProfileRegistry {
  /**
   * @param {object} options
   * @param {string} [options.dir] 프로파일 디렉터리. 기본은 detection/config/site-profiles.
   * @param {string} [options.defaultProfileId] 대상 ID 로 못 찾았을 때 쓸 프로파일 ID.
   *   비우면 generic 으로 간다. 모르는 ID 면 기동 시 던진다.
   * @param {(line: string) => void} [options.warn] 경고 출력. 기본 console.warn.
   */
  constructor({ dir = DEFAULT_PROFILES_DIR, defaultProfileId = "", warn = console.warn } = {}) {
    this.dir = dir;
    this.profiles = loadProfilesFrom(dir);
    this.warn = warn;
    this.warnedTargets = new Set();

    const configured = String(defaultProfileId || "").trim();
    if (configured && !this.profiles.has(configured)) {
      throw new SiteProfileError(
        `unknown DETECTION_DEFAULT_SITE_PROFILE: ${configured} ` +
        `(loaded: ${[...this.profiles.keys()].join(", ")})`
      );
    }
    this.defaultProfileId = configured || FALLBACK_PROFILE_ID;

    this._warnAboutDisabledFeatures();
  }

  // 기동 시 한 번만. 프로파일 × 기능 개수(대략 3 × 18)로 유계이고, 요청마다 찍지
  // 않으므로 로그가 범람할 수 없다. 운영자는 새벽 첫 요청이 아니라 기동 때 안다.
  _warnAboutDisabledFeatures() {
    for (const profile of this.profiles.values()) {
      for (const feature of profile.disabledFeatures) {
        this.warn(
          `[siteProfile] profile=${profile.profileId} feature=${feature} ` +
          `missing -> disabled (no profile)`
        );
      }
      for (const feature of profile.genericDefaultFeatures) {
        this.warn(
          `[siteProfile] profile=${profile.profileId} feature=${feature} ` +
          `uses the generic default -> not verified for this site`
        );
      }
    }
  }

  /**
   * 대상 ID 를 프로파일로 해결한다.
   * 순서: <targetId>.json → DETECTION_DEFAULT_SITE_PROFILE → generic.
   * @returns {{profile: object, profileId: string, source: string, targetId: string|null}}
   */
  forTarget(targetId) {
    const id = typeof targetId === "string" ? targetId : null;
    const direct = id ? this.profiles.get(id) : undefined;
    if (direct) {
      return { profile: direct, profileId: direct.profileId, source: "target-id", targetId: id };
    }
    this._warnAboutUnmappedTarget(id);
    const profile = this.profiles.get(this.defaultProfileId);
    return {
      profile,
      profileId: profile.profileId,
      source: this.defaultProfileId === FALLBACK_PROFILE_ID ? "generic-fallback" : "default-env",
      targetId: id,
    };
  }

  // 대상 ID 당 한 번만. 프로파일이 아예 없는 대상(새 TARGET_CHOICES 항목)만 해당한다.
  _warnAboutUnmappedTarget(targetId) {
    const key = targetId === null ? "(none)" : targetId;
    if (this.warnedTargets.has(key)) return;
    if (this.warnedTargets.size >= MAX_WARNED_TARGETS) return;
    this.warnedTargets.add(key);
    const profile = this.profiles.get(this.defaultProfileId);
    this.warn(
      `[siteProfile] target=${key} has no profile -> using ${this.defaultProfileId}; ` +
      `${profile.disabledFeatures.length} features disabled (no profile)`
    );
  }

  /** 관리 API 용 상태. 점수와 무관한 별도 채널이다 — blTags 에는 아무것도 넣지 않는다. */
  status(activeTargetId = null) {
    const active = this.forTarget(activeTargetId);
    return {
      defaultProfileId: this.defaultProfileId,
      active: {
        targetId: active.targetId,
        profileId: active.profileId,
        source: active.source,
        label: active.profile.label,
      },
      profiles: [...this.profiles.values()].map((profile) => ({
        profileId: profile.profileId,
        label: profile.label,
        disabledFeatures: [...profile.disabledFeatures],
        genericDefaultFeatures: [...profile.genericDefaultFeatures],
      })),
      unmappedTargets: [...this.warnedTargets],
    };
  }
}

module.exports = { SiteProfileRegistry, DEFAULT_PROFILES_DIR, FALLBACK_PROFILE_ID };
