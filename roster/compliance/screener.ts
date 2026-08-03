/**
 * Screening orchestrator — pure over already-loaded snapshots.
 *
 * `loadAll` turns a set of ListSourcePorts into SourceInputs (snapshot or
 * typed gap — an unreachable source degrades the report, never crashes it).
 * `screenSubject` runs the matching engine over the inputs and assembles a
 * ScreeningReport where every match cites the attested list downloads it was
 * found on, and every SCREENED source records the list versions it was
 * screened against even when nothing matched (provable absence).
 */
import {
  bestNameMatch,
  bestNameMatchPrepared,
  MATCH_THRESHOLD,
  prepareName,
  severityForMatch,
  walletsEqual,
  type PreparedName,
} from "./matching.js";
import { preparedNamesFor } from "./prepared-names.js";
import type {
  ListSnapshot,
  ListVersion,
  Match,
  MatchSeverity,
  PerSourceResult,
  ScreeningReport,
  ScreeningSubject,
  SourceId,
  SourceInput,
  ListSourcePort,
  Citations,
  Verdict,
} from "./types.js";
import { makeMatch, subjectNames, SOURCE_META } from "./types.js";

/** Keep reports readable: matches per source, best-first. */
export const MAX_MATCHES_PER_SOURCE = 25;

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/** Load every source; a throwing load becomes a gap, not a crash. */
export async function loadAll(sources: readonly ListSourcePort[]): Promise<SourceInput[]> {
  return Promise.all(
    sources.map(async (source): Promise<SourceInput> => {
      try {
        return { sourceId: source.id, snapshot: await source.load() };
      } catch (err) {
        return { sourceId: source.id, gap: (err as Error).message };
      }
    }),
  );
}

// ---------------------------------------------------------------------------
// Per-source screening
// ---------------------------------------------------------------------------

function excerpt(s: string, max = 200): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

function screenNamesAgainstEntries(
  prepared: readonly PreparedName[],
  snapshot: ListSnapshot,
  listRefs: Citations,
  label: string,
): Match[] {
  const matches: Match[] = [];
  // Full scan — every authoritative sanctions-list entry is compared. The only
  // change from a naive scan is that each entry name is normalized ONCE (at
  // parse time, memoized) instead of on every request; the scoring is identical.
  const entryPrepared = preparedNamesFor(snapshot.entries);
  for (let i = 0; i < snapshot.entries.length; i++) {
    const entry = snapshot.entries[i];
    const best = bestNameMatchPrepared(prepared, entryPrepared[i]);
    if (!best) continue;
    const severity = severityForMatch(best.method, best.score);
    if (!severity) continue;
    matches.push(
      makeMatch({
        listEntryExcerpt: excerpt(`${label} ${entry.entryId} "${entry.name}" [${entry.program}] kind=${entry.entryKind}`),
        matchedName: best.entryName,
        subjectName: best.subjectName,
        score: round6(best.score),
        method: best.method,
        program: entry.program,
        severity,
        citations: listRefs,
      }),
    );
  }
  return matches;
}

/**
 * PEP (aggregator) screening: same fuzzy name pipeline, but every hit is a
 * `pep-match` (exact → "match", fuzzy → capped "potential-match") and is
 * labeled AGGREGATOR so a reader treats it as a lead to confirm against the
 * cited primary dataset, not a primary-list hit.
 */
/** Score one PEP entry index; null when it does not reach a reportable severity. */
function pepMatchAt(
  i: number,
  prepared: readonly PreparedName[],
  entryPrepared: readonly PreparedName[][],
  snapshot: ListSnapshot,
  listRefs: Citations,
  label: string,
): Match | null {
  const best = bestNameMatchPrepared(prepared, entryPrepared[i]);
  if (!best) return null;
  const severity = severityForMatch("pep-match", best.score);
  if (!severity) return null;
  const entry = snapshot.entries[i];
  return makeMatch({
    listEntryExcerpt: excerpt(`${label} ${entry.entryId} "${entry.name}" [${entry.program}] kind=${entry.entryKind} (AGGREGATOR — confirm vs primary)`),
    matchedName: best.entryName,
    subjectName: best.subjectName,
    score: round6(best.score),
    method: "pep-match",
    program: entry.program,
    severity,
    citations: listRefs,
  });
}

/**
 * PEP (aggregator) screening — a FULL SCAN of every entry.
 *
 * A blocking/candidate index was tried to cut the ~2M-entry PEP scan, but no
 * token/n-gram index can be a safe SUPERSET of Jaro-Winkler fuzzy matching:
 * transposition typos (e.g. "Ykui Siamra" ~ "Yuki Sharma") score highly yet
 * share no token OR n-gram, so an index can DROP a real hit — a FALSE CLEAR,
 * the one failure sanctions/PEP screening must never make. (The removed index's
 * own adversarial fuzz test caught exactly this.) Correctness beats speed here:
 * we full-scan. Speed comes instead from the in-process parsed-name memo
 * (`preparedNamesFor`), so the per-request cost is the comparison loop alone —
 * NOT a re-parse/re-normalize of the 219 MB list on every request.
 */
function screenNamesAgainstPep(prepared: readonly PreparedName[], snapshot: ListSnapshot, listRefs: Citations, label: string): Match[] {
  const entryPrepared = preparedNamesFor(snapshot.entries);
  const matches: Match[] = [];
  for (let i = 0; i < snapshot.entries.length; i++) {
    const m = pepMatchAt(i, prepared, entryPrepared, snapshot, listRefs, label);
    if (m) matches.push(m);
  }
  return matches;
}

function screenWalletAgainstSdn(address: string, snapshot: ListSnapshot, listRefs: Citations): Match[] {
  const matches: Match[] = [];
  for (const dca of snapshot.addresses) {
    if (!walletsEqual(address, dca.address)) continue;
    matches.push(
      makeMatch({
        listEntryExcerpt: excerpt(`SDN ${dca.entryId} "${dca.entryName}" digital-currency ${dca.currency} ${dca.address}`),
        matchedName: dca.address,
        subjectName: address,
        score: 1,
        method: "wallet-exact",
        program: `digital-currency (${dca.currency}) of ${dca.entryName}`,
        severity: "match",
        citations: listRefs,
      }),
    );
  }
  return matches;
}

function screenEntityAgainstEdgar(prepared: readonly PreparedName[], snapshot: ListSnapshot, listRefs: Citations): Match[] {
  const matches: Match[] = [];
  for (const filer of snapshot.filers) {
    let hit: { score: number; subjectName: string; matchedName: string } | null = null;

    for (const s of prepared) {
      // Ticker equality is an unambiguous registration signal.
      if (s.key === filer.ticker.toLowerCase()) {
        hit = { score: 1, subjectName: s.raw, matchedName: filer.ticker };
        break;
      }
    }
    if (!hit) {
      // EDGAR is an existence signal, not a sanctions screen — require a
      // STRONG correspondence (all subject tokens contained in the title,
      // or a fuzzy score clearing the hard MATCH threshold), otherwise a
      // 10k-title registry sprays ~0.86 near-misses on any two-token name.
      const titlePrepared = prepareName(filer.title);
      for (const s of prepared) {
        if (s.tokens.size === 0) continue;
        const subset = [...s.tokens].every((t) => titlePrepared.tokens.has(t));
        const best = bestNameMatch([s], [filer.title]);
        const fuzzy = best && best.score >= MATCH_THRESHOLD ? best.score : 0;
        const score = Math.max(fuzzy, subset ? 0.9 : 0);
        if (score > 0 && (!hit || score > hit.score)) {
          hit = { score, subjectName: s.raw, matchedName: filer.title };
        }
      }
    }
    if (!hit) continue;

    matches.push(
      makeMatch({
        listEntryExcerpt: excerpt(`EDGAR CIK ${filer.cik} "${filer.title}" ticker=${filer.ticker}`),
        matchedName: hit.matchedName,
        subjectName: hit.subjectName,
        score: round6(hit.score),
        method: "edgar-registration",
        program: "registered US filer (SEC EDGAR company tickers)",
        severity: "info",
        citations: listRefs,
      }),
    );
  }
  return matches;
}

function round6(n: number): number {
  return Math.round(n * 1e6) / 1e6;
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/** Worst severity wins; "info" never escalates the verdict. */
export function aggregateVerdict(severities: readonly MatchSeverity[]): Verdict {
  if (severities.includes("match")) return "match";
  if (severities.includes("potential-match")) return "potential-match";
  return "clear";
}

// ---------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------

export function screenSubject(subject: ScreeningSubject, inputs: readonly SourceInput[]): ScreeningReport {
  const listVersions: ListVersion[] = [];
  const perSource: PerSourceResult[] = [];

  // Names are fuzzy-screened for people/entities; a wallet subject's "name"
  // is its address, which would only garbage-match against human names.
  const prepared = subject.kind === "wallet" ? [] : subjectNames(subject).map(prepareName);

  for (const input of inputs) {
    if ("gap" in input) {
      perSource.push({ sourceId: input.sourceId, status: "gap", reason: input.gap });
      continue;
    }
    const { snapshot } = input;

    // Register this source's downloads as citable list versions.
    const refs = snapshot.downloads.map((d) => {
      const version: ListVersion = { ...d, id: `L${listVersions.length + 1}`, sourceId: input.sourceId };
      listVersions.push(version);
      return version.id;
    });
    if (refs.length === 0) {
      // A snapshot with zero downloads has nothing to cite — that's a bug in
      // the source adapter, and screening against it would be unprovable.
      throw new Error(`source ${input.sourceId} produced a snapshot with no attested downloads`);
    }
    const listRefs = refs as Citations;

    let matches: Match[] = [];
    if (input.sourceId === "sec-edgar") {
      if (subject.kind === "entity") matches = screenEntityAgainstEdgar(prepared, snapshot, listRefs);
    } else if (input.sourceId === "opensanctions-pep") {
      if (prepared.length > 0) matches = screenNamesAgainstPep(prepared, snapshot, listRefs, sourceLabel(input.sourceId));
    } else {
      // OFAC SDN, UN, EU, UK — authoritative sanctions lists, same name pipeline.
      if (prepared.length > 0) matches = screenNamesAgainstEntries(prepared, snapshot, listRefs, sourceLabel(input.sourceId));
      if (subject.walletAddress && input.sourceId === "ofac-sdn") {
        matches.push(...screenWalletAgainstSdn(subject.walletAddress, snapshot, listRefs));
      }
    }

    matches.sort((a, b) => b.score - a.score);
    const kept = matches.slice(0, MAX_MATCHES_PER_SOURCE);
    perSource.push({
      sourceId: input.sourceId,
      status: "screened",
      listRefs,
      matches: kept,
      sourceVerdict: aggregateVerdict(kept.map((m) => m.severity)),
    });
  }

  const severities = perSource.flatMap((p) => (p.status === "screened" ? p.matches.map((m) => m.severity) : []));

  return {
    version: 2,
    subject,
    screenedAt: new Date().toISOString(),
    panel: inputs.map((i) => i.sourceId),
    perSource,
    listVersions,
    screeningComplete: perSource.every((p) => p.status === "screened"),
    verdict: aggregateVerdict(severities),
  };
}

export function sourceLabel(id: SourceId): string {
  return SOURCE_META[id].label;
}
