/**
 * Finding derivation — deterministic, rule-based. Every rule reads extracted
 * fields off one or more EvidenceItems and emits findings through a builder
 * that assigns ids and goes through `makeFinding`, so an uncited finding
 * cannot be produced here even by a buggy rule.
 *
 * Ages are computed against an injected `now` so tests (and reruns over the
 * same evidence) are fully deterministic.
 */
import type { EvidenceItem, EvidenceSource, Finding, Severity } from "./types.js";
import { makeFinding } from "./types.js";

export const THRESHOLDS = {
  /** npm: last publish older than this is stale. */
  stalePublishDays: 730,
  /** npm: last publish within this is "actively published". */
  freshPublishDays: 90,
  /** npm: package first published within this is immature (supply-chain risk). */
  newPackageDays: 90,
  /** npm: package older than this is well-established. */
  establishedPackageDays: 730,
  /** npm: monthly downloads below this = low adoption. */
  lowDownloadsPerMonth: 1_000,
  /** npm: monthly downloads at/above this = wide adoption. */
  highDownloadsPerMonth: 100_000,
  /** GitHub: no push for longer than this = stale repo. */
  staleRepoDays: 365,
  /** GitHub: open-issue/star ratio above this (with enough stars) = caution. */
  issueRatioCaution: 0.5,
  issueRatioMinStars: 50,
  /** Token: market-cap rank at/under this = established. */
  rankEstablished: 50,
  /** Token: rank beyond this (or unranked) = long tail. */
  rankLongTail: 500,
  /** Token: 24h volume / market cap under this = thin liquidity. */
  liquidityThin: 0.01,
  /** Token: fully-diluted-valuation / market-cap over this = dilution overhang. */
  fdvOverhang: 3,
  /** Token: fewer distinct PR contributors than this = bus-factor caution. */
  devContributorsLow: 3,
  /** Token: combined twitter+telegram followers under this = tiny community. */
  communityLow: 1_000,
  /** Token: drawdown from ATH (percent, negative) breakpoints. */
  drawdownRedFlagPct: -90,
  drawdownCautionPct: -70,
} as const;

function daysBetween(iso: string, now: Date): number | null {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / 86_400_000);
}

class FindingBuilder {
  readonly findings: Finding[] = [];

  add(rule: string, severity: Severity, title: string, detail: string, citations: readonly string[]): void {
    this.findings.push(
      makeFinding({ id: `F${this.findings.length + 1}`, rule, severity, title, detail, citations }),
    );
  }
}

function num(e: EvidenceItem, field: string): number | null {
  const v = e.extracted[field];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(e: EvidenceItem, field: string): string | null {
  const v = e.extracted[field];
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Emit the shared "source responded but is unusable" caution for a not-ok
 * item (403 rate limit, 404, 5xx, or unparseable body). The unavailability
 * itself is attested evidence, so the finding stays citable.
 */
function unavailableFinding(b: FindingBuilder, e: EvidenceItem, label: string): void {
  const status = num(e, "httpStatus") ?? e.status;
  const reason = str(e, "reason") ?? `upstream responded ${status}`;
  b.add(
    `${e.source}-unavailable`,
    "caution",
    `${label} unavailable`,
    `${label} could not be used (${reason}); related claims are unverifiable in this report and the assessment is degraded accordingly.`,
    [e.id],
  );
}

// ---------------------------------------------------------------------------
// npm rules
// ---------------------------------------------------------------------------

function npmRegistryRules(b: FindingBuilder, e: EvidenceItem, now: Date): void {
  const version = str(e, "latestVersion") ?? "latest";

  if (e.extracted.deprecated === true) {
    const msg = str(e, "deprecatedMessage");
    b.add(
      "npm-deprecated",
      "red-flag",
      `Latest version ${version} is deprecated`,
      `The npm registry marks the latest version as deprecated${msg ? `: "${msg}"` : ""}. Do not adopt without a migration plan.`,
      [e.id],
    );
  }

  const lastPublishAt = str(e, "lastPublishAt");
  const publishAge = lastPublishAt ? daysBetween(lastPublishAt, now) : null;
  if (publishAge !== null) {
    if (publishAge > THRESHOLDS.stalePublishDays) {
      b.add(
        "npm-publish-age",
        "caution",
        `No release in ${publishAge} days`,
        `The latest publish (${version}) landed ${lastPublishAt}; longer than ${THRESHOLDS.stalePublishDays} days suggests the package is unmaintained.`,
        [e.id],
      );
    } else {
      const fresh = publishAge <= THRESHOLDS.freshPublishDays;
      b.add(
        "npm-publish-age",
        "info",
        fresh ? `Actively published (${publishAge} days since last release)` : `Last release ${publishAge} days ago`,
        `The latest publish (${version}) landed ${lastPublishAt}.`,
        [e.id],
      );
    }
  }

  const createdAt = str(e, "createdAt");
  const packageAge = createdAt ? daysBetween(createdAt, now) : null;
  if (packageAge !== null) {
    if (packageAge < THRESHOLDS.newPackageDays) {
      b.add(
        "npm-package-age",
        "caution",
        `New package: first published ${packageAge} days ago`,
        `The package was first published ${createdAt} — under ${THRESHOLDS.newPackageDays} days old. New packages carry elevated supply-chain risk (typosquats, unproven maintainers).`,
        [e.id],
      );
    } else if (packageAge >= THRESHOLDS.establishedPackageDays) {
      b.add(
        "npm-package-age",
        "info",
        `Established package: first published ${packageAge} days ago`,
        `The package has existed since ${createdAt}, longer than ${THRESHOLDS.establishedPackageDays} days.`,
        [e.id],
      );
    } else {
      b.add(
        "npm-package-age",
        "info",
        `Package first published ${packageAge} days ago`,
        `The package was first published ${createdAt}.`,
        [e.id],
      );
    }
  }

  const maintainers = num(e, "maintainersCount");
  if (maintainers !== null) {
    if (maintainers <= 1) {
      b.add(
        "npm-single-maintainer",
        "caution",
        "Single-maintainer package",
        `Only ${maintainers} maintainer is listed on the registry — a bus-factor and account-takeover risk.`,
        [e.id],
      );
    } else {
      b.add(
        "npm-single-maintainer",
        "info",
        `${maintainers} maintainers listed`,
        "Multiple registry maintainers reduce bus-factor risk.",
        [e.id],
      );
    }
  }

  const license = str(e, "license");
  if (license) {
    b.add("npm-license", "info", `License declared: ${license}`, `The registry doc declares "${license}" for ${version}.`, [e.id]);
  } else {
    b.add(
      "npm-license",
      "red-flag",
      "No license declared",
      "The registry doc carries no license for the latest version — legally unusable in most commercial settings.",
      [e.id],
    );
  }

  if (!str(e, "githubRepo")) {
    b.add(
      "npm-no-repo",
      "caution",
      "No linked GitHub repository",
      "The registry doc does not link a resolvable GitHub repository, so source-level checks (archived/stale/issues) could not be run.",
      [e.id],
    );
  }
}

function npmDownloadsRules(b: FindingBuilder, e: EvidenceItem): void {
  const downloads = num(e, "downloadsLastMonth");
  if (downloads === null) return;
  if (downloads < THRESHOLDS.lowDownloadsPerMonth) {
    b.add(
      "npm-downloads",
      "caution",
      `Low adoption: ${downloads.toLocaleString("en-US")} downloads last month`,
      `Fewer than ${THRESHOLDS.lowDownloadsPerMonth.toLocaleString("en-US")} monthly downloads — few eyes on the code, higher abandonment risk.`,
      [e.id],
    );
  } else if (downloads >= THRESHOLDS.highDownloadsPerMonth) {
    b.add(
      "npm-downloads",
      "info",
      `Widely adopted: ${downloads.toLocaleString("en-US")} downloads last month`,
      "High download volume implies broad usage and many eyes on regressions.",
      [e.id],
    );
  } else {
    b.add(
      "npm-downloads",
      "info",
      `Moderate adoption: ${downloads.toLocaleString("en-US")} downloads last month`,
      "Download volume is neither negligible nor mass-market.",
      [e.id],
    );
  }
}

/**
 * GitHub Global Advisory DB. A package that names published advisories is a
 * concrete, attested security signal: critical/high → red-flag, medium/low →
 * caution, none → info. Advisories match the package across all versions (not
 * necessarily the latest), which the detail states plainly.
 */
function githubAdvisoryRules(b: FindingBuilder, e: EvidenceItem): void {
  const count = num(e, "advisoryCount");
  if (count === null) return;

  if (count === 0) {
    b.add(
      "gh-advisories",
      "info",
      "No known security advisories",
      "The GitHub Global Advisory DB lists no advisories naming this package.",
      [e.id],
    );
    return;
  }

  const worst = str(e, "worstSeverity") ?? "unknown";
  const list = Array.isArray(e.extracted.advisories) ? (e.extracted.advisories as Array<Record<string, unknown>>) : [];
  const sample = list
    .slice(0, 3)
    .map((a) => `${String(a.ghsaId)} (${String(a.severity)}${a.vulnerableRange ? `, affects ${String(a.vulnerableRange)}` : ""}): ${String(a.summary)}`)
    .join("; ");
  const severity: Severity = worst === "critical" || worst === "high" ? "red-flag" : "caution";
  b.add(
    "gh-advisories",
    severity,
    `${count} known security advisor${count === 1 ? "y" : "ies"} (worst: ${worst})`,
    `The GitHub Global Advisory DB names this package in ${count} advisor${count === 1 ? "y" : "ies"} (highest severity ${worst}). ` +
      `These match the package across versions, not necessarily the latest — confirm your resolved version against each range. Top: ${sample || "(details omitted)"}.`,
    [e.id],
  );
}

function githubRules(b: FindingBuilder, e: EvidenceItem, now: Date): void {
  const name = str(e, "fullName") ?? "repository";

  if (e.extracted.archived === true) {
    b.add(
      "gh-archived",
      "red-flag",
      `Repository ${name} is archived`,
      "GitHub marks the source repository read-only/archived — no future fixes or security patches.",
      [e.id],
    );
  }

  const pushedAt = str(e, "pushedAt");
  const pushAge = pushedAt ? daysBetween(pushedAt, now) : null;
  if (pushAge !== null) {
    if (pushAge > THRESHOLDS.staleRepoDays) {
      b.add(
        "gh-push-age",
        "caution",
        `Repository stale: no push in ${pushAge} days`,
        `Last push to ${name} was ${pushedAt}; longer than ${THRESHOLDS.staleRepoDays} days suggests development has stopped.`,
        [e.id],
      );
    } else {
      b.add("gh-push-age", "info", `Repository active (pushed ${pushAge} days ago)`, `Last push to ${name} was ${pushedAt}.`, [e.id]);
    }
  }

  const stars = num(e, "stars");
  const openIssues = num(e, "openIssues");
  if (stars !== null && openIssues !== null) {
    const ratio = openIssues / Math.max(stars, 1);
    if (stars >= THRESHOLDS.issueRatioMinStars && ratio > THRESHOLDS.issueRatioCaution) {
      b.add(
        "gh-issue-ratio",
        "caution",
        `High open-issue load (${openIssues.toLocaleString("en-US")} open vs ${stars.toLocaleString("en-US")} stars)`,
        `Open-issue/star ratio ${ratio.toFixed(2)} exceeds ${THRESHOLDS.issueRatioCaution} — triage may not be keeping up.`,
        [e.id],
      );
    } else {
      b.add(
        "gh-issue-ratio",
        "info",
        `${stars.toLocaleString("en-US")} stars, ${openIssues.toLocaleString("en-US")} open issues`,
        `Open-issue/star ratio ${ratio.toFixed(2)}.`,
        [e.id],
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Token rules
// ---------------------------------------------------------------------------

function coingeckoRules(b: FindingBuilder, e: EvidenceItem): void {
  const rank = num(e, "marketCapRank");
  if (rank !== null && rank <= THRESHOLDS.rankEstablished) {
    b.add("cg-rank", "info", `Market-cap rank #${rank}`, "A top-tier rank implies established market presence.", [e.id]);
  } else if (rank === null || rank > THRESHOLDS.rankLongTail) {
    b.add(
      "cg-rank",
      "caution",
      rank === null ? "Unranked by market cap" : `Long-tail market-cap rank #${rank}`,
      `Rank ${rank === null ? "unavailable" : `#${rank}`} — beyond the top ${THRESHOLDS.rankLongTail} means thin coverage and higher failure risk.`,
      [e.id],
    );
  } else {
    b.add("cg-rank", "info", `Market-cap rank #${rank}`, "Mid-table market-cap rank.", [e.id]);
  }

  const mcap = num(e, "marketCapUsd");
  const volume = num(e, "volume24hUsd");
  if (mcap !== null && volume !== null && mcap > 0) {
    const ratio = volume / mcap;
    if (ratio < THRESHOLDS.liquidityThin) {
      b.add(
        "cg-liquidity",
        "caution",
        `Thin liquidity: 24h volume is ${(ratio * 100).toFixed(2)}% of market cap`,
        `Volume/market-cap ratio ${ratio.toFixed(4)} is under ${THRESHOLDS.liquidityThin} — exits at size will move the price.`,
        [e.id],
      );
    } else {
      b.add(
        "cg-liquidity",
        "info",
        `Liquidity: 24h volume is ${(ratio * 100).toFixed(1)}% of market cap`,
        `Volume/market-cap ratio ${ratio.toFixed(4)}.`,
        [e.id],
      );
    }
  }

  const fdv = num(e, "fullyDilutedValuationUsd");
  if (fdv !== null && mcap !== null && mcap > 0) {
    const ratio = fdv / mcap;
    if (ratio >= THRESHOLDS.fdvOverhang) {
      b.add(
        "cg-supply-overhang",
        "caution",
        `Dilution overhang: fully-diluted valuation is ${ratio.toFixed(1)}x market cap`,
        `FDV/market-cap ratio ${ratio.toFixed(2)} at/over ${THRESHOLDS.fdvOverhang} — most of the supply is not yet circulating, so future unlocks can dilute holders.`,
        [e.id],
      );
    } else {
      b.add(
        "cg-supply-overhang",
        "info",
        `Circulating supply: fully-diluted valuation is ${ratio.toFixed(2)}x market cap`,
        `FDV/market-cap ratio ${ratio.toFixed(2)} — limited future-dilution overhang.`,
        [e.id],
      );
    }
  }

  const contributors = num(e, "devPullRequestContributors");
  if (contributors !== null) {
    if (contributors < THRESHOLDS.devContributorsLow) {
      b.add(
        "cg-dev-contributors",
        "caution",
        `Thin developer base: ${contributors.toLocaleString("en-US")} PR contributor(s)`,
        `CoinGecko developer data reports ${contributors} distinct pull-request contributor(s) — under ${THRESHOLDS.devContributorsLow}, a bus-factor concern.`,
        [e.id],
      );
    } else {
      b.add(
        "cg-dev-contributors",
        "info",
        `${contributors.toLocaleString("en-US")} developer PR contributors`,
        "Multiple pull-request contributors reduce bus-factor risk per CoinGecko developer data.",
        [e.id],
      );
    }
  }

  const commits = num(e, "devCommits4w");
  if (commits !== null) {
    if (commits === 0) {
      b.add(
        "cg-dev-activity",
        "caution",
        "No developer commits in the last 4 weeks",
        "CoinGecko developer data shows zero commits over the trailing month — development may be dormant.",
        [e.id],
      );
    } else {
      b.add(
        "cg-dev-activity",
        "info",
        `${commits.toLocaleString("en-US")} developer commits in the last 4 weeks`,
        "Ongoing developer activity per CoinGecko developer data.",
        [e.id],
      );
    }
  }

  const twitter = num(e, "twitterFollowers");
  const telegram = num(e, "telegramUsers");
  const community = (twitter ?? 0) + (telegram ?? 0);
  if (twitter === null && telegram === null) {
    // No data is not the same as a tiny community — CoinGecko omits these
    // stats for some coins. Say so, don't manufacture a caution.
    b.add(
      "cg-community",
      "info",
      "Community stats not reported by CoinGecko",
      "Twitter/Telegram community fields are absent from the coin document; community size is unassessed.",
      [e.id],
    );
  } else if (community < THRESHOLDS.communityLow) {
    b.add(
      "cg-community",
      "caution",
      `Tiny community (${community.toLocaleString("en-US")} followers across Twitter/Telegram)`,
      `Combined community stats fall under ${THRESHOLDS.communityLow.toLocaleString("en-US")} — little independent scrutiny.`,
      [e.id],
    );
  } else {
    b.add(
      "cg-community",
      "info",
      `Community: ${(twitter ?? 0).toLocaleString("en-US")} Twitter followers, ${(telegram ?? 0).toLocaleString("en-US")} Telegram users`,
      "Community stats per CoinGecko community data.",
      [e.id],
    );
  }

  const drawdown = num(e, "athChangePct");
  if (drawdown !== null) {
    if (drawdown <= THRESHOLDS.drawdownRedFlagPct) {
      b.add(
        "cg-drawdown",
        "red-flag",
        `Price ${Math.abs(drawdown).toFixed(1)}% below all-time high`,
        `A drawdown past ${Math.abs(THRESHOLDS.drawdownRedFlagPct)}% from ATH is consistent with a collapsed or abandoned asset.`,
        [e.id],
      );
    } else if (drawdown <= THRESHOLDS.drawdownCautionPct) {
      b.add(
        "cg-drawdown",
        "caution",
        `Price ${Math.abs(drawdown).toFixed(1)}% below all-time high`,
        `Deep drawdown from ATH (past ${Math.abs(THRESHOLDS.drawdownCautionPct)}%).`,
        [e.id],
      );
    } else {
      b.add(
        "cg-drawdown",
        "info",
        `Price ${Math.abs(drawdown).toFixed(1)}% below all-time high`,
        "Drawdown from ATH within ordinary market range.",
        [e.id],
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const SOURCE_LABEL: Record<EvidenceSource, string> = {
  "npm-registry": "npm registry document",
  "npm-downloads": "npm download counts",
  "github-advisories": "GitHub security advisories",
  "github-repo": "GitHub repository metadata",
  "coingecko-coin": "CoinGecko coin data",
};

export function deriveFindings(evidence: EvidenceItem[], now: Date): Finding[] {
  const b = new FindingBuilder();

  for (const item of evidence) {
    if (!item.ok) {
      unavailableFinding(b, item, SOURCE_LABEL[item.source]);
      continue;
    }
    switch (item.source) {
      case "npm-registry":
        npmRegistryRules(b, item, now);
        break;
      case "npm-downloads":
        npmDownloadsRules(b, item);
        break;
      case "github-advisories":
        githubAdvisoryRules(b, item);
        break;
      case "github-repo":
        githubRules(b, item, now);
        break;
      case "coingecko-coin":
        coingeckoRules(b, item);
        break;
    }
  }

  return b.findings;
}
