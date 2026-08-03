/**
 * Compliance Screener — types and ports.
 *
 * Defensive compliance tooling: screen a counterparty (person, entity, or
 * wallet address) against PUBLIC government sanctions/registry lists —
 * OFAC SDN (+ alternate names), the UN Security Council consolidated list,
 * and SEC EDGAR company tickers (a registration-existence signal, not a
 * risk) — with every list download flowing through the shared
 * AttestedFetchPort so the resulting ScreeningReport is verifiable either
 * way: a match cites the attested list it was found on, and a CLEAR verdict
 * still cites the attested lists it was screened AGAINST (provable absence:
 * "screened against SDN version fetched at T").
 *
 * Attestation machinery is reused from the oracle desk (MOCK DAHR — an
 * ephemeral ed25519 signer, loudly labeled; real DAHR is a port swap there).
 * No DACS lifecycle wiring. Node builtins only.
 */
import type { MockDahrAttestation } from "../oracle-desk/types.js";

export type { AttestedFetchPort, AttestedFetchResult, MockDahrAttestation } from "../oracle-desk/types.js";
export type { AttestedRecord } from "../oracle-desk/attested-fetch.js";

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

export type SubjectKind = "person" | "entity" | "wallet";

export interface ScreeningSubject {
  /** Primary name (for `kind: "wallet"` this is typically the address). */
  name: string;
  aliases?: string[];
  country?: string;
  walletAddress?: string;
  kind: SubjectKind;
}

/** All names the subject is screened under (primary + aliases, non-empty). */
export function subjectNames(subject: ScreeningSubject): string[] {
  return [subject.name, ...(subject.aliases ?? [])].filter((n) => n.trim().length > 0);
}

/** Filesystem-safe slug for the out/ directory name. */
export function subjectSlug(subject: ScreeningSubject): string {
  return `${subject.kind}-${subject.name.toLowerCase().replace(/[^a-z0-9.-]+/g, "_").slice(0, 60)}`;
}

// ---------------------------------------------------------------------------
// List sources
// ---------------------------------------------------------------------------

export type SourceId =
  | "ofac-sdn"
  | "un-consolidated"
  | "eu-consolidated"
  | "uk-hmt"
  | "opensanctions-pep"
  | "sec-edgar";

/**
 * The advertised screening panel, in screen order. Sanctions lists first
 * (worst-wins risk), then the PEP aggregator, then the EDGAR registry signal.
 */
export const SOURCE_IDS: readonly SourceId[] = [
  "ofac-sdn",
  "un-consolidated",
  "eu-consolidated",
  "uk-hmt",
  "opensanctions-pep",
  "sec-edgar",
];

export type SourceCategory = "sanctions" | "pep" | "registry";
/**
 * primary   — an authoritative list published BY the issuing authority.
 * aggregator — a third party that re-publishes primary data (matches must be
 *              treated as leads to confirm against the primary source, and are
 *              labeled as such in the report). OpenSanctions PEP is aggregator.
 */
export type SourceProvenance = "primary" | "aggregator";

export interface SourceMeta {
  label: string;
  authority: string;
  category: SourceCategory;
  provenance: SourceProvenance;
}

export const SOURCE_META: Record<SourceId, SourceMeta> = {
  "ofac-sdn": { label: "OFAC SDN", authority: "US Treasury OFAC", category: "sanctions", provenance: "primary" },
  "un-consolidated": { label: "UN", authority: "UN Security Council", category: "sanctions", provenance: "primary" },
  "eu-consolidated": { label: "EU", authority: "European Union (FSD)", category: "sanctions", provenance: "primary" },
  "uk-hmt": { label: "UK OFSI", authority: "UK HM Treasury (OFSI)", category: "sanctions", provenance: "primary" },
  "opensanctions-pep": { label: "PEP", authority: "OpenSanctions (aggregator)", category: "pep", provenance: "aggregator" },
  "sec-edgar": { label: "EDGAR", authority: "US SEC", category: "registry", provenance: "primary" },
};

/** One sanctions-list entry (SDN row or UN individual/entity). */
export interface ListEntry {
  /** Source-local id, e.g. "SDN-30393" or the UN reference number. */
  entryId: string;
  name: string;
  /** Alternate names (SDN ALT.CSV rows / UN ALIAS_NAME fields). */
  aliases: string[];
  /** Sanctions program / list type, e.g. "DPRK3" or "DPRK". */
  program: string;
  /** individual | entity | vessel | aircraft | unknown (lowercased source value). */
  entryKind: string;
}

/** A digital-currency address extracted from SDN remarks/alt data. */
export interface DigitalCurrencyAddress {
  /** OFAC currency tag, e.g. "XBT", "ETH". */
  currency: string;
  address: string;
  entryId: string;
  entryName: string;
}

/** One SEC EDGAR company-tickers row. */
export interface EdgarFiler {
  cik: string;
  ticker: string;
  title: string;
}

export type FetchMode = "fresh" | "cached" | "fixture";

/**
 * One attested list download. The attestation covers url|fetchedAt|bodyHash
 * — list bodies are megabytes, so the report keeps hashes only (the
 * dd-researcher over-64KB discipline applied to everything here) and the
 * record stays verifiable body-free via `verifyAttestedRecord`.
 */
export interface ListDownload {
  /** Human label, e.g. "SDN.CSV", "ALT.CSV", "consolidated.xml". */
  label: string;
  url: string;
  /** ISO-8601 time the bytes were ORIGINALLY fetched (cache-hit keeps it). */
  fetchedAt: string;
  /** sha256 hex of the raw list body actually used. */
  bodyHash: string;
  mode: FetchMode;
  /**
   * Publication / generation date DECLARED BY the list body itself (EU export
   * generationDate, UK "Last Updated", UN dateGenerated), when the format
   * carries one — part of the evidence chain: which VERSION was screened, not
   * just when we fetched it. Absent when the source embeds no such marker.
   */
  publicationDate?: string;
  attestation: MockDahrAttestation;
}

/** A ListDownload as recorded in a report, addressable by citation id. */
export interface ListVersion extends ListDownload {
  /** "L1", "L2", … — what matches and listRefs cite. */
  id: string;
  sourceId: SourceId;
}

/** Everything one source yields after download + parse. */
export interface ListSnapshot {
  sourceId: SourceId;
  /** ≥1 attested download this snapshot was parsed from. */
  downloads: ListDownload[];
  entries: ListEntry[];
  /** SDN only; empty elsewhere. */
  addresses: DigitalCurrencyAddress[];
  /** EDGAR only; empty elsewhere. */
  filers: EdgarFiler[];
  stats: { entries: number; aliases: number; addresses: number; filers: number; malformedRows: number };
}

export interface ListSourcePort {
  readonly id: SourceId;
  /** Download (through the AttestedFetchPort, cache-aware) and parse. */
  load(): Promise<ListSnapshot>;
}

// ---------------------------------------------------------------------------
// Matches (citation-by-construction)
// ---------------------------------------------------------------------------

/** Non-empty citation list — the type-level half of the zero-citation ban. */
export type Citations = [string, ...string[]];

export type MatchMethod =
  | "exact"
  | "jaro-winkler"
  | "token-overlap"
  | "wallet-exact"
  | "edgar-registration"
  | "pep-match";

export type MatchSeverity = "match" | "potential-match" | "info";

export interface Match {
  /** Short rendering of the list entry the subject hit. */
  listEntryExcerpt: string;
  /** The list-side name (or address) that scored. */
  matchedName: string;
  /** The subject-side name (or address) that scored. */
  subjectName: string;
  /** 0..1. */
  score: number;
  method: MatchMethod;
  /** Sanctions program / reason, e.g. "DPRK3" or "registered US filer". */
  program: string;
  severity: MatchSeverity;
  /** ListVersion ids this match derives from. NEVER empty. */
  citations: Citations;
}

/**
 * The only sanctioned Match constructor. Throws if `citations` is empty —
 * combined with the non-empty tuple type this makes an uncited match
 * impossible by construction, not just by convention.
 */
export function makeMatch(input: Omit<Match, "citations"> & { citations: readonly string[] }): Match {
  if (input.citations.length === 0) {
    throw new Error(`match on "${input.matchedName}" has zero citations — every match must cite an attested list download`);
  }
  return { ...input, citations: [...input.citations] as Citations };
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/** What the screener receives per source: a loaded snapshot or a typed gap. */
export type SourceInput =
  | { sourceId: SourceId; snapshot: ListSnapshot }
  | { sourceId: SourceId; gap: string };

export type PerSourceResult =
  | {
      sourceId: SourceId;
      status: "screened";
      /**
       * ListVersion ids screened against — NEVER empty. This is the provable
       * absence: a clear source still cites exactly which attested list
       * versions the subject was NOT found on.
       */
      listRefs: Citations;
      matches: Match[];
      /**
       * Worst severity among THIS source's matches ("clear" when none) — the
       * per-list verdict of the evidence chain. Re-derived by the verifier
       * from the recorded matches, so it cannot disagree with them.
       */
      sourceVerdict: Verdict;
    }
  | { sourceId: SourceId; status: "gap"; reason: string };

export type Verdict = "clear" | "potential-match" | "match";

export interface ScreeningReport {
  version: 2;
  subject: ScreeningSubject;
  screenedAt: string;
  /**
   * The intended screening panel. Every id appears exactly once in perSource
   * (as `screened` or `gap`). Declaring it makes "a source was silently
   * dropped to hide a hit" a verifier-detectable tamper, not an invisible one.
   */
  panel: SourceId[];
  perSource: PerSourceResult[];
  /** All attested list downloads used, addressable by citation id. */
  listVersions: ListVersion[];
  /**
   * True iff EVERY panel source screened (no gaps). The strong regulator claim
   * is "clear AND complete"; a "clear" with `screeningComplete: false` means
   * clear only on the lists that were reachable — never a false all-clear.
   */
  screeningComplete: boolean;
  /** Worst severity across sources; "info" matches never escalate it. */
  verdict: Verdict;
}

/** Result of the third-party re-verification of an emitted report. */
export interface VerifyScreeningResult {
  valid: boolean;
  problems: string[];
  /** How many list-download attestation signatures were re-verified. */
  attestationsChecked: number;
  /** How many matches had citations resolved + severity recomputed. */
  matchesChecked: number;
  /** Verdict recomputed from the recorded matches (must equal recorded). */
  recomputedVerdict?: Verdict;
  /** Completeness recomputed from the recorded gaps (must equal recorded). */
  recomputedComplete?: boolean;
}
