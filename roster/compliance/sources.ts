/**
 * List sources — downloaders + parsers per public list, real and fixture.
 *
 * Every download flows through an AttestedFetchPort. Fresh bytes get the
 * port's attestation; cache hits are re-attested over the CACHED bytes with
 * their original fetchedAt (the attestation always covers the actual bytes
 * parsed). Bodies never leave this module — snapshots carry parsed entries
 * plus body-free attested download records (the >64KB hash-only discipline
 * applied unconditionally: these lists are megabytes).
 *
 * Parsers are dependency-free and defensive: a hand-rolled CSV state machine
 * (quotes, "" escapes, newlines-in-quotes), a targeted regex/string
 * extractor for the UN XML (no XML parser), and shape-checked JSON for
 * EDGAR. Malformed rows/blocks are counted and skipped, never fatal.
 */
import { stat } from "node:fs/promises";
import { FakeAttestedFetch, MockDahrAttestor, sha256Hex } from "../oracle-desk/attested-fetch.js";
import { CACHE_TTL_MS, cacheEntryPath, readCachedBody, writeCachedBody } from "./cache.js";
import type { SourceId } from "./types.js";
import type {
  AttestedFetchPort,
  AttestedFetchResult,
  DigitalCurrencyAddress,
  EdgarFiler,
  ListDownload,
  ListEntry,
  ListSnapshot,
  ListSourcePort,
} from "./types.js";

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

export const SDN_URLS = [
  "https://sanctionslist.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
  "https://www.treasury.gov/ofac/downloads/sdn.csv",
] as const;

export const ALT_URLS = [
  "https://sanctionslist.ofac.treas.gov/api/PublicationPreview/exports/ALT.CSV",
  "https://www.treasury.gov/ofac/downloads/alt.csv",
] as const;

export const UN_CONSOLIDATED_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml";

/**
 * EU consolidated financial sanctions list (FSD), full XML v1.1. The public
 * download uses a fixed anonymous token (base64 "token-2017"); the endpoint
 * serves the whole list, no key. Verified live 2026-07 (root
 * `<export generationDate=...>` with `<sanctionEntity>` / `<nameAlias>`).
 */
export const EU_CONSOLIDATED_URL =
  "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw";

/** UK OFSI / HM Treasury consolidated list, official CSV (2022 format). */
export const UK_HMT_URLS = [
  "https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.csv",
] as const;

/**
 * OpenSanctions PEP dataset, free "simple" CSV (CC-BY 4.0). AGGREGATOR: it
 * re-publishes primary registries and annotates PEP status; matches are leads
 * to confirm against the cited primary dataset, not primary hits themselves.
 * The live file is ~190MB (verified 2026-07), so live ingestion needs a bulk
 * pipeline or the keyed search API — the demo/tests screen a fixture excerpt
 * through the same parse + attestation path (see README/report notes).
 */
export const OPENSANCTIONS_PEP_URL = "https://data.opensanctions.org/datasets/latest/peps/targets.simple.csv";

export const EDGAR_TICKERS_URL = "https://www.sec.gov/files/company_tickers.json";

// ---------------------------------------------------------------------------
// Real fetch adapter — like oracle-desk's RealAttestedFetch, but with a
// proper identifying User-Agent (SEC EDGAR rejects anonymous defaults) and a
// longer timeout sized for multi-megabyte list downloads.
// ---------------------------------------------------------------------------

/**
 * SEC guidance wants a User-Agent declaring who you are with a contact
 * (anonymous/tool-shaped UAs get 403 at the WAF, verified live 2026-07-07).
 * Override with COMPLIANCE_USER_AGENT to identify yourself.
 */
export const COMPLIANCE_USER_AGENT =
  process.env.COMPLIANCE_USER_AGENT ??
  "dacs-agent-reference/0.1 contact@example.invalid";

export class RealComplianceFetch implements AttestedFetchPort {
  constructor(
    private readonly attestor: MockDahrAttestor = new MockDahrAttestor(),
    private readonly timeoutMs = 25_000,
  ) {}

  async attestFetch(url: string): Promise<AttestedFetchResult> {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(this.timeoutMs),
      headers: {
        accept: "text/csv, application/json, application/xml, text/plain;q=0.9, */*;q=0.8",
        "user-agent": COMPLIANCE_USER_AGENT,
      },
    });
    const body = await response.text();
    const fetchedAt = new Date().toISOString();
    const bodyHash = sha256Hex(body);
    return { url, fetchedAt, status: response.status, bodyHash, body, attestation: this.attestor.attest(url, fetchedAt, bodyHash) };
  }
}

// ---------------------------------------------------------------------------
// Cache-aware attested download
// ---------------------------------------------------------------------------

export interface ListFetchContext {
  port: AttestedFetchPort;
  /** Enable the TTL body cache when set. */
  cacheDir?: string;
  ttlMs?: number;
  /** Label downloads "fixture" instead of "fresh" (canned-body adapters). */
  fixture?: boolean;
  nowMs?: () => number;
  /** Signer for cache-hit attestations (fresh fetches use the port's). */
  attestor?: MockDahrAttestor;
}

/**
 * Fetch one list body through the context: cache hit → re-attest the cached
 * bytes (original fetchedAt preserved); miss → attested network fetch, non-
 * 2xx throws, 2xx body cached for next time.
 */
export async function fetchListBody(
  ctx: ListFetchContext,
  url: string,
  label: string,
): Promise<{ download: ListDownload; body: string }> {
  if (ctx.cacheDir) {
    const hit = await readCachedBody(ctx.cacheDir, url, ctx.ttlMs ?? CACHE_TTL_MS, ctx.nowMs?.() ?? Date.now());
    if (hit) {
      const bodyHash = sha256Hex(hit.body);
      const attestor = (ctx.attestor ??= new MockDahrAttestor());
      return {
        body: hit.body,
        download: { label, url, fetchedAt: hit.fetchedAt, bodyHash, mode: "cached", attestation: attestor.attest(url, hit.fetchedAt, bodyHash) },
      };
    }
  }

  const res = await ctx.port.attestFetch(url);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`${label}: HTTP ${res.status} from ${url}`);
  }
  if (ctx.cacheDir) await writeCachedBody(ctx.cacheDir, url, res.fetchedAt, res.body);
  return {
    body: res.body,
    download: { label, url, fetchedAt: res.fetchedAt, bodyHash: res.bodyHash, mode: ctx.fixture ? "fixture" : "fresh", attestation: res.attestation },
  };
}

/** Try urls in order (primary → legacy); throw the combined failure. */
async function fetchFirst(ctx: ListFetchContext, urls: readonly string[], label: string): Promise<{ download: ListDownload; body: string }> {
  const failures: string[] = [];
  for (const url of urls) {
    try {
      return await fetchListBody(ctx, url, label);
    } catch (err) {
      failures.push(`${url}: ${(err as Error).message}`);
    }
  }
  throw new Error(`${label}: all urls failed — ${failures.join(" | ")}`);
}

// ---------------------------------------------------------------------------
// In-process parsed-snapshot memo
// ---------------------------------------------------------------------------
//
// The disk cache (cache.ts) keeps re-DOWNLOAD off the hot path, but every
// request still RE-READ + RE-PARSED the cached bodies — for the OpenSanctions
// PEP list that is ~219 MB parsed into ~2M entries, tens of seconds per call.
// This memo parses each source's snapshot ONCE per process and reuses it until
// the underlying cached body changes or the TTL lapses.
//
// The version key is a cheap stat() probe (mtime+size) over the source's cache
// files — a refreshed list rewrites its cache file (new mtime/size) and cleanly
// invalidates the memo; an expired body is re-fetched by the real load, which
// rewrites the file and likewise bumps the probe. Matching behavior is
// unchanged: the reused snapshot's `entries` are byte-for-byte what a re-parse
// would produce. Memo is keyed by cacheDir + source id, so distinct cache dirs
// (e.g. per-test temp dirs) never collide; fixture/no-cache loads skip it.

interface SnapshotMemo {
  snapshot: ListSnapshot;
  probe: string;
  at: number;
}

const SNAPSHOT_MEMO = new Map<string, SnapshotMemo>();

/** Cheap change-detector: (mtime,size) of each of the source's cache files. */
async function probeVersion(cacheDir: string, urls: readonly string[]): Promise<string> {
  const parts: string[] = [];
  for (const url of urls) {
    try {
      const s = await stat(cacheEntryPath(cacheDir, url));
      parts.push(`${url}:${s.mtimeMs}:${s.size}`);
    } catch {
      parts.push(`${url}:none`);
    }
  }
  return parts.join("|");
}

/**
 * Wrap a source's real download+parse with the in-process memo. Only active
 * when a cacheDir is configured (the live/gateway path); fixture and cache-less
 * loads always parse fresh (they are small and their identity is not stable).
 */
async function memoizedLoad(
  id: SourceId,
  ctx: ListFetchContext,
  urls: readonly string[],
  doLoad: () => Promise<ListSnapshot>,
): Promise<ListSnapshot> {
  if (!ctx.cacheDir) return doLoad();
  const key = `${ctx.cacheDir}::${id}`;
  const now = ctx.nowMs?.() ?? Date.now();
  const ttl = ctx.ttlMs ?? CACHE_TTL_MS;
  const probe = await probeVersion(ctx.cacheDir, urls);
  const memo = SNAPSHOT_MEMO.get(key);
  if (memo && memo.probe === probe && now - memo.at <= ttl) return memo.snapshot;
  const snapshot = await doLoad();
  // Re-probe AFTER the load: a cold/expired load writes (or rewrites) the cache
  // bodies, so the freshly-written files' (mtime,size) is the version the next
  // request will see. Storing the pre-load probe would miss on every call.
  const freshProbe = await probeVersion(ctx.cacheDir, urls);
  SNAPSHOT_MEMO.set(key, { snapshot, probe: freshProbe, at: now });
  return snapshot;
}

/** Drop the in-process parsed-snapshot memo (tests / forced refresh). */
export function clearComplianceMemo(): void {
  SNAPSHOT_MEMO.clear();
}

// ---------------------------------------------------------------------------
// CSV parsing (state machine — quotes, "" escapes, newlines inside quotes)
// ---------------------------------------------------------------------------

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let sawAny = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      sawAny = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
      sawAny = true;
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
      if (sawAny || field.length > 0) {
        row.push(field);
        rows.push(row);
      }
      row = [];
      field = "";
      sawAny = false;
    } else {
      field += ch;
      sawAny = true;
    }
  }
  if (sawAny || field.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** OFAC null marker: "-0-" (with stray whitespace) means "no value". */
function ofacValue(raw: string | undefined): string {
  const v = (raw ?? "").trim();
  return v === "-0-" ? "" : v;
}

// ---------------------------------------------------------------------------
// Digital-currency address extraction (SDN remarks / alt remarks)
// ---------------------------------------------------------------------------

const DIGITAL_CURRENCY_RE = /Digital Currency Address\s*-\s*([A-Z0-9]{2,6})\s+([a-zA-Z0-9]{10,110})/g;

export function extractDigitalCurrencyAddresses(text: string, entryId: string, entryName: string): DigitalCurrencyAddress[] {
  const out: DigitalCurrencyAddress[] = [];
  for (const m of text.matchAll(DIGITAL_CURRENCY_RE)) {
    out.push({ currency: m[1], address: m[2], entryId, entryName });
  }
  return out;
}

// ---------------------------------------------------------------------------
// OFAC SDN (SDN.CSV: ent_num, SDN_Name, SDN_Type, Program, …, Remarks[11];
//           ALT.CSV: ent_num, alt_num, alt_type, alt_name, alt_remarks)
// ---------------------------------------------------------------------------

export interface ParsedSdn {
  entries: ListEntry[];
  addresses: DigitalCurrencyAddress[];
  malformedRows: number;
}

export function parseSdnCsv(sdnCsv: string, altCsv?: string): ParsedSdn {
  const entries: ListEntry[] = [];
  const addresses: DigitalCurrencyAddress[] = [];
  const byEntNum = new Map<string, ListEntry>();
  let malformedRows = 0;

  const rows = parseCsv(sdnCsv);
  for (const [i, row] of rows.entries()) {
    const entNum = (row[0] ?? "").trim();
    if (!/^\d+$/.test(entNum)) {
      // A non-numeric first field on row 0 is a header; elsewhere it's junk.
      if (i > 0) malformedRows += 1;
      continue;
    }
    if (row.length < 12) {
      malformedRows += 1;
      continue;
    }
    const name = ofacValue(row[1]);
    if (name.length === 0) {
      malformedRows += 1;
      continue;
    }
    const entryKind = ofacValue(row[2]).toLowerCase() || "unknown";
    const program = ofacValue(row[3]) || "unknown";
    // Exactly 12 columns in the published format; tolerate extras by joining.
    const remarks = row
      .slice(11)
      .map((c) => ofacValue(c))
      .filter((c) => c.length > 0)
      .join(", ");

    const entry: ListEntry = { entryId: `SDN-${entNum}`, name, aliases: [], program, entryKind };
    entries.push(entry);
    byEntNum.set(entNum, entry);
    addresses.push(...extractDigitalCurrencyAddresses(remarks, entry.entryId, name));
  }

  if (altCsv !== undefined) {
    const altRows = parseCsv(altCsv);
    for (const [i, row] of altRows.entries()) {
      const entNum = (row[0] ?? "").trim();
      if (!/^\d+$/.test(entNum)) {
        if (i > 0) malformedRows += 1;
        continue;
      }
      if (row.length < 4) {
        malformedRows += 1;
        continue;
      }
      const altName = ofacValue(row[3]);
      const altRemarks = ofacValue(row[4]);
      const entry = byEntNum.get(entNum);
      if (!entry) {
        malformedRows += 1; // alt row for an entity we never saw
        continue;
      }
      if (altName.length > 0 && !entry.aliases.includes(altName)) entry.aliases.push(altName);
      if (altRemarks.length > 0) {
        addresses.push(...extractDigitalCurrencyAddresses(altRemarks, entry.entryId, entry.name));
      }
    }
  }

  return { entries, addresses, malformedRows };
}

// ---------------------------------------------------------------------------
// UN Security Council consolidated list (targeted string extraction, no XML
// parser — FIRST_NAME/SECOND_NAME/… and ALIAS_NAME fields, defensively)
// ---------------------------------------------------------------------------

const XML_ENTITY_RE = /&(amp|lt|gt|quot|apos|#x?[0-9a-fA-F]+);/g;

export function decodeXmlEntities(s: string): string {
  return s.replace(XML_ENTITY_RE, (whole, name: string) => {
    switch (name) {
      case "amp":
        return "&";
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        const code = name.startsWith("#x") || name.startsWith("#X")
          ? Number.parseInt(name.slice(2), 16)
          : Number.parseInt(name.slice(1), 10);
        return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
      }
    }
  });
}

/** First occurrence of <TAG>…</TAG> in `block`, trimmed + entity-decoded. */
function xmlTag(block: string, tag: string): string {
  const m = new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`).exec(block);
  return m ? decodeXmlEntities(m[1]).trim() : "";
}

function xmlTagAll(block: string, tag: string): string[] {
  const out: string[] = [];
  for (const m of block.matchAll(new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`, "g"))) {
    const v = decodeXmlEntities(m[1]).trim();
    if (v.length > 0) out.push(v);
  }
  return out;
}

/**
 * Value of attribute `attr` in an opening-tag string, entity-decoded. `attr`
 * is always a hardcoded constant here — never list-derived — so the RegExp is
 * not an injection surface. Untrusted list bytes are only ever the SUBJECT of
 * the match, never compiled into a pattern.
 */
function xmlAttr(tag: string, attr: string): string {
  const m = new RegExp(`\\b${attr}="([^"]*)"`).exec(tag);
  return m ? decodeXmlEntities(m[1]).trim() : "";
}

export interface ParsedUn {
  entries: ListEntry[];
  malformedRows: number;
  /** Root `dateGenerated` attribute, when present. */
  publicationDate?: string;
}

function parseUnBlock(block: string, kind: "individual" | "entity", fallbackId: string): ListEntry | null {
  const nameParts = [xmlTag(block, "FIRST_NAME"), xmlTag(block, "SECOND_NAME"), xmlTag(block, "THIRD_NAME"), xmlTag(block, "FOURTH_NAME")];
  const name = nameParts.filter((p) => p.length > 0).join(" ").replace(/\s+/g, " ").trim();
  if (name.length === 0) return null;

  const aliases: string[] = [];
  for (const alias of xmlTagAll(block, "ALIAS_NAME")) {
    if (alias !== name && !aliases.includes(alias)) aliases.push(alias);
  }
  const entryId = xmlTag(block, "REFERENCE_NUMBER") || xmlTag(block, "DATAID") || fallbackId;
  const program = xmlTag(block, "UN_LIST_TYPE") || "UN";
  return { entryId: `UN-${entryId}`, name, aliases, program, entryKind: kind };
}

export function parseUnConsolidatedXml(xml: string): ParsedUn {
  const entries: ListEntry[] = [];
  let malformedRows = 0;
  let i = 0;

  for (const m of xml.matchAll(/<INDIVIDUAL>([\s\S]*?)<\/INDIVIDUAL>/g)) {
    i += 1;
    const entry = parseUnBlock(m[1], "individual", `individual-${i}`);
    if (entry) entries.push(entry);
    else malformedRows += 1;
  }
  for (const m of xml.matchAll(/<ENTITY>([\s\S]*?)<\/ENTITY>/g)) {
    i += 1;
    const entry = parseUnBlock(m[1], "entity", `entity-${i}`);
    if (entry) entries.push(entry);
    else malformedRows += 1;
  }
  const rootTag = /<CONSOLIDATED_LIST\b([^>]*)>/.exec(xml);
  const publicationDate = rootTag ? xmlAttr(rootTag[1], "dateGenerated") || undefined : undefined;
  return { entries, malformedRows, publicationDate };
}

// ---------------------------------------------------------------------------
// EU consolidated financial sanctions list (FSD XML v1.1) — attribute-based:
// <sanctionEntity euReferenceNumber logicalId> with <subjectType code> and one
// or more <nameAlias wholeName firstName middleName lastName>. Names live in
// ATTRIBUTES (not element text), so a targeted opening-tag + attribute scan
// (no XML parser) mirrors the UN approach.
// ---------------------------------------------------------------------------

export interface ParsedEu {
  entries: ListEntry[];
  malformedRows: number;
  /** Root `<export generationDate=...>`, when present. */
  publicationDate?: string;
}

function euSubjectKind(code: string): string {
  const c = code.toLowerCase();
  if (c === "person") return "individual";
  if (c === "enterprise") return "entity";
  return c || "unknown";
}

/** Names from a <nameAlias> opening tag: wholeName, else firstName+middle+last. */
function euNameFromAlias(tag: string): string {
  const whole = xmlAttr(tag, "wholeName");
  if (whole.length > 0) return whole.replace(/\s+/g, " ").trim();
  const parts = [xmlAttr(tag, "firstName"), xmlAttr(tag, "middleName"), xmlAttr(tag, "lastName")];
  return parts.filter((p) => p.length > 0).join(" ").replace(/\s+/g, " ").trim();
}

export function parseEuConsolidatedXml(xml: string): ParsedEu {
  const entries: ListEntry[] = [];
  let malformedRows = 0;

  const rootTag = /<export\b([^>]*)>/.exec(xml);
  const publicationDate = rootTag ? xmlAttr(rootTag[1], "generationDate") || undefined : undefined;

  let i = 0;
  for (const block of xml.matchAll(/<sanctionEntity\b([^>]*)>([\s\S]*?)<\/sanctionEntity>/g)) {
    i += 1;
    const attrs = block[1];
    const inner = block[2];

    const names: string[] = [];
    for (const alias of inner.matchAll(/<nameAlias\b([^>]*)>/g)) {
      const name = euNameFromAlias(alias[1]);
      if (name.length > 0 && !names.includes(name)) names.push(name);
    }
    if (names.length === 0) {
      malformedRows += 1;
      continue;
    }

    const subjectTag = /<subjectType\b([^>]*)>/.exec(inner);
    const entryKind = subjectTag ? euSubjectKind(xmlAttr(subjectTag[1], "code")) : "unknown";
    const regTag = /<regulation\b([^>]*)>/.exec(inner);
    const program = (regTag ? xmlAttr(regTag[1], "programme") : "") || "EU";
    const ref = xmlAttr(attrs, "euReferenceNumber") || xmlAttr(attrs, "logicalId") || `eu-${i}`;

    entries.push({ entryId: `EU-${ref}`, name: names[0], aliases: names.slice(1), program, entryKind });
  }

  return { entries, malformedRows, publicationDate };
}

// ---------------------------------------------------------------------------
// UK OFSI / HM Treasury consolidated list (ConList.csv, 2022 format):
//   line 1  -> "Last Updated,<dd/mm/yyyy>"
//   line 2  -> header row (Name 1..6, Group Type, Alias Type, Regime, Group ID)
//   line 3+ -> one row PER NAME; rows sharing a Group ID are one designation
//             (primary name + variants + AKAs). Columns addressed BY HEADER
//             NAME, so extra/reordered columns don't shift the parse.
// ---------------------------------------------------------------------------

export interface ParsedUk {
  entries: ListEntry[];
  malformedRows: number;
  /** Header "Last Updated" date, when present. */
  publicationDate?: string;
}

interface UkGroup {
  kind: string;
  program: string;
  primaryNames: string[];
  aliasNames: string[];
}

export function parseUkHmtCsv(csv: string): ParsedUk {
  const rows = parseCsv(csv);
  let malformedRows = 0;
  let publicationDate: string | undefined;

  // Optional "Last Updated,<date>" preamble line.
  let headerIdx = -1;
  for (const [idx, row] of rows.entries()) {
    if (row[0] && row[0].trim().toLowerCase() === "last updated" && row[1]) {
      publicationDate = row[1].trim();
    }
    if (row.some((c) => c.trim() === "Group ID") && row.some((c) => /^Name \d$/.test(c.trim()))) {
      headerIdx = idx;
      break;
    }
  }
  if (headerIdx === -1) {
    // No recognizable header → the format drifted; report zero entries so the
    // live floor trips and the source degrades (never a false clear).
    return { entries: [], malformedRows: rows.length, publicationDate };
  }

  const header = rows[headerIdx].map((c) => c.trim());
  const col = (name: string): number => header.indexOf(name);
  const nameCols = [1, 2, 3, 4, 5, 6].map((n) => col(`Name ${n}`)).filter((c) => c >= 0);
  const groupTypeCol = col("Group Type");
  const aliasTypeCol = col("Alias Type");
  const regimeCol = col("Regime");
  const groupIdCol = col("Group ID");
  if (nameCols.length === 0 || groupIdCol < 0) {
    return { entries: [], malformedRows: rows.length, publicationDate };
  }

  const groups = new Map<string, UkGroup>();
  for (let r = headerIdx + 1; r < rows.length; r++) {
    const row = rows[r];
    if (row.length === 1 && row[0].trim().length === 0) continue; // blank line
    const groupId = (row[groupIdCol] ?? "").trim();
    // Name 1..5 then Name 6 (family name last), per OFSI convention.
    const order = [1, 2, 3, 4, 5, 6].map((n) => col(`Name ${n}`)).filter((c) => c >= 0);
    const fullName = order.map((c) => (row[c] ?? "").trim()).filter((v) => v.length > 0).join(" ").replace(/\s+/g, " ").trim();
    if (groupId.length === 0 || fullName.length === 0) {
      malformedRows += 1;
      continue;
    }
    let g = groups.get(groupId);
    if (!g) {
      g = { kind: "unknown", program: "UK", primaryNames: [], aliasNames: [] };
      groups.set(groupId, g);
    }
    const gt = groupTypeCol >= 0 ? (row[groupTypeCol] ?? "").trim().toLowerCase() : "";
    if (gt === "individual") g.kind = "individual";
    else if (gt === "entity") g.kind = "entity";
    else if (g.kind === "unknown" && gt.length > 0) g.kind = gt;
    const regime = regimeCol >= 0 ? (row[regimeCol] ?? "").trim() : "";
    if (regime.length > 0 && g.program === "UK") g.program = regime;
    const aliasType = aliasTypeCol >= 0 ? (row[aliasTypeCol] ?? "").trim().toLowerCase() : "";
    if (aliasType.startsWith("primary")) g.primaryNames.push(fullName);
    else g.aliasNames.push(fullName);
  }

  const entries: ListEntry[] = [];
  for (const [groupId, g] of groups) {
    const allNames = [...g.primaryNames, ...g.aliasNames];
    if (allNames.length === 0) {
      malformedRows += 1;
      continue;
    }
    const name = allNames[0];
    const aliases: string[] = [];
    for (const n of allNames.slice(1)) if (n !== name && !aliases.includes(n)) aliases.push(n);
    entries.push({ entryId: `UK-${groupId}`, name, aliases, program: g.program, entryKind: g.kind });
  }

  return { entries, malformedRows, publicationDate };
}

// ---------------------------------------------------------------------------
// OpenSanctions PEP "simple" CSV (AGGREGATOR). Columns addressed by header
// name; aliases are ";"-separated; `dataset` is the primary provenance shown
// as the program. schema Person -> individual, else entity.
// ---------------------------------------------------------------------------

export interface ParsedPep {
  entries: ListEntry[];
  malformedRows: number;
}

export function parseOpenSanctionsPepCsv(csv: string): ParsedPep {
  const rows = parseCsv(csv);
  const entries: ListEntry[] = [];
  let malformedRows = 0;
  if (rows.length < 2) return { entries, malformedRows: rows.length };

  const header = rows[0].map((c) => c.trim().toLowerCase());
  const col = (name: string): number => header.indexOf(name);
  const idCol = col("id");
  const nameCol = col("name");
  const aliasCol = col("aliases");
  const schemaCol = col("schema");
  const datasetCol = col("dataset");
  if (nameCol < 0) return { entries: [], malformedRows: rows.length };

  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    if (row.length === 1 && row[0].trim().length === 0) continue;
    const name = (row[nameCol] ?? "").trim();
    if (name.length === 0) {
      malformedRows += 1;
      continue;
    }
    const aliases: string[] = [];
    if (aliasCol >= 0) {
      for (const a of (row[aliasCol] ?? "").split(";")) {
        const v = a.trim();
        if (v.length > 0 && v !== name && !aliases.includes(v)) aliases.push(v);
      }
    }
    const schema = schemaCol >= 0 ? (row[schemaCol] ?? "").trim().toLowerCase() : "";
    const entryKind = schema === "person" ? "individual" : schema.length > 0 ? "entity" : "unknown";
    const dataset = datasetCol >= 0 ? (row[datasetCol] ?? "").trim() : "";
    const id = idCol >= 0 ? (row[idCol] ?? "").trim() : "";
    entries.push({
      entryId: `PEP-${id || r}`,
      name,
      aliases,
      program: dataset.length > 0 ? `PEP: ${dataset}` : "PEP",
      entryKind,
    });
  }
  return { entries, malformedRows };
}

// ---------------------------------------------------------------------------
// SEC EDGAR company tickers ({"0": {cik_str, ticker, title}, …})
// ---------------------------------------------------------------------------

export interface ParsedEdgar {
  filers: EdgarFiler[];
  malformedRows: number;
}

export function parseEdgarTickers(body: string): ParsedEdgar {
  const parsed: unknown = JSON.parse(body);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("EDGAR tickers: expected a JSON object");
  }
  const filers: EdgarFiler[] = [];
  let malformedRows = 0;
  for (const value of Object.values(parsed as Record<string, unknown>)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      malformedRows += 1;
      continue;
    }
    const row = value as Record<string, unknown>;
    const cik = typeof row.cik_str === "number" || typeof row.cik_str === "string" ? String(row.cik_str) : "";
    const ticker = typeof row.ticker === "string" ? row.ticker.trim() : "";
    const title = typeof row.title === "string" ? row.title.trim() : "";
    if (cik.length === 0 || ticker.length === 0 || title.length === 0) {
      malformedRows += 1;
      continue;
    }
    filers.push({ cik, ticker, title });
  }
  return { filers, malformedRows };
}

// ---------------------------------------------------------------------------
// Source adapters
// ---------------------------------------------------------------------------

function emptyStats(): ListSnapshot["stats"] {
  return { entries: 0, aliases: 0, addresses: 0, filers: 0, malformedRows: 0 };
}

/**
 * Sanity floors for LIVE loads: a "successful" download that parses into a
 * near-empty list means the published format drifted — better to throw (and
 * let the caller fall back) than to silently screen against nothing.
 * Fixture-mode loads skip the floor.
 */
const MIN_LIVE_SDN_ENTRIES = 50;
const MIN_LIVE_UN_ENTRIES = 50;
const MIN_LIVE_EU_ENTRIES = 50;
const MIN_LIVE_UK_ENTRIES = 20;
const MIN_LIVE_PEP_ENTRIES = 20;
const MIN_LIVE_EDGAR_FILERS = 100;

/** Attach a list-declared publication date to the primary download record. */
function withPublicationDate(download: ListDownload, publicationDate?: string): ListDownload {
  return publicationDate ? { ...download, publicationDate } : download;
}

export class OfacSdnSource implements ListSourcePort {
  readonly id = "ofac-sdn" as const;

  constructor(private readonly ctx: ListFetchContext) {}

  async load(): Promise<ListSnapshot> {
    return memoizedLoad(this.id, this.ctx, [...SDN_URLS, ...ALT_URLS], async () => {
      const sdn = await fetchFirst(this.ctx, SDN_URLS, "SDN.CSV");
      const downloads: ListDownload[] = [sdn.download];

      // Alternate names enrich matching but their absence isn't fatal.
      let altBody: string | undefined;
      try {
        const alt = await fetchFirst(this.ctx, ALT_URLS, "ALT.CSV");
        altBody = alt.body;
        downloads.push(alt.download);
      } catch {
        altBody = undefined;
      }

      const parsed = parseSdnCsv(sdn.body, altBody);
      if (!this.ctx.fixture && parsed.entries.length < MIN_LIVE_SDN_ENTRIES) {
        throw new Error(`SDN.CSV parsed into only ${parsed.entries.length} entries — format drift suspected`);
      }
      return {
        sourceId: this.id,
        downloads,
        entries: parsed.entries,
        addresses: parsed.addresses,
        filers: [],
        stats: {
          ...emptyStats(),
          entries: parsed.entries.length,
          aliases: parsed.entries.reduce((n, e) => n + e.aliases.length, 0),
          addresses: parsed.addresses.length,
          malformedRows: parsed.malformedRows,
        },
      };
    });
  }
}

export class UnConsolidatedSource implements ListSourcePort {
  readonly id = "un-consolidated" as const;

  constructor(private readonly ctx: ListFetchContext) {}

  async load(): Promise<ListSnapshot> {
    return memoizedLoad(this.id, this.ctx, [UN_CONSOLIDATED_URL], async () => {
      const xml = await fetchListBody(this.ctx, UN_CONSOLIDATED_URL, "consolidated.xml");
      const parsed = parseUnConsolidatedXml(xml.body);
      if (!this.ctx.fixture && parsed.entries.length < MIN_LIVE_UN_ENTRIES) {
        throw new Error(`UN consolidated.xml parsed into only ${parsed.entries.length} entries — format drift suspected`);
      }
      return {
        sourceId: this.id,
        downloads: [withPublicationDate(xml.download, parsed.publicationDate)],
        entries: parsed.entries,
        addresses: [],
        filers: [],
        stats: {
          ...emptyStats(),
          entries: parsed.entries.length,
          aliases: parsed.entries.reduce((n, e) => n + e.aliases.length, 0),
          malformedRows: parsed.malformedRows,
        },
      };
    });
  }
}

export class EuConsolidatedSource implements ListSourcePort {
  readonly id = "eu-consolidated" as const;

  constructor(private readonly ctx: ListFetchContext) {}

  async load(): Promise<ListSnapshot> {
    return memoizedLoad(this.id, this.ctx, [EU_CONSOLIDATED_URL], async () => {
      const xml = await fetchListBody(this.ctx, EU_CONSOLIDATED_URL, "eu-consolidated.xml");
      const parsed = parseEuConsolidatedXml(xml.body);
      if (!this.ctx.fixture && parsed.entries.length < MIN_LIVE_EU_ENTRIES) {
        throw new Error(`EU consolidated list parsed into only ${parsed.entries.length} entries — format drift suspected`);
      }
      return {
        sourceId: this.id,
        downloads: [withPublicationDate(xml.download, parsed.publicationDate)],
        entries: parsed.entries,
        addresses: [],
        filers: [],
        stats: {
          ...emptyStats(),
          entries: parsed.entries.length,
          aliases: parsed.entries.reduce((n, e) => n + e.aliases.length, 0),
          malformedRows: parsed.malformedRows,
        },
      };
    });
  }
}

export class UkHmtSource implements ListSourcePort {
  readonly id = "uk-hmt" as const;

  constructor(private readonly ctx: ListFetchContext) {}

  async load(): Promise<ListSnapshot> {
    return memoizedLoad(this.id, this.ctx, UK_HMT_URLS, async () => {
      const csv = await fetchFirst(this.ctx, UK_HMT_URLS, "ConList.csv");
      const parsed = parseUkHmtCsv(csv.body);
      if (!this.ctx.fixture && parsed.entries.length < MIN_LIVE_UK_ENTRIES) {
        throw new Error(`UK OFSI ConList.csv parsed into only ${parsed.entries.length} entries — format drift suspected`);
      }
      return {
        sourceId: this.id,
        downloads: [withPublicationDate(csv.download, parsed.publicationDate)],
        entries: parsed.entries,
        addresses: [],
        filers: [],
        stats: {
          ...emptyStats(),
          entries: parsed.entries.length,
          aliases: parsed.entries.reduce((n, e) => n + e.aliases.length, 0),
          malformedRows: parsed.malformedRows,
        },
      };
    });
  }
}

export class OpenSanctionsPepSource implements ListSourcePort {
  readonly id = "opensanctions-pep" as const;

  constructor(private readonly ctx: ListFetchContext) {}

  async load(): Promise<ListSnapshot> {
    return memoizedLoad(this.id, this.ctx, [OPENSANCTIONS_PEP_URL], async () => {
      const csv = await fetchListBody(this.ctx, OPENSANCTIONS_PEP_URL, "peps.targets.simple.csv");
      const parsed = parseOpenSanctionsPepCsv(csv.body);
      if (!this.ctx.fixture && parsed.entries.length < MIN_LIVE_PEP_ENTRIES) {
        throw new Error(`OpenSanctions PEP list parsed into only ${parsed.entries.length} entries — format drift suspected`);
      }
      return {
        sourceId: this.id,
        downloads: [csv.download],
        entries: parsed.entries,
        addresses: [],
        filers: [],
        stats: {
          ...emptyStats(),
          entries: parsed.entries.length,
          aliases: parsed.entries.reduce((n, e) => n + e.aliases.length, 0),
          malformedRows: parsed.malformedRows,
        },
      };
    });
  }
}

export class SecEdgarSource implements ListSourcePort {
  readonly id = "sec-edgar" as const;

  constructor(private readonly ctx: ListFetchContext) {}

  async load(): Promise<ListSnapshot> {
    return memoizedLoad(this.id, this.ctx, [EDGAR_TICKERS_URL], async () => {
      const json = await fetchListBody(this.ctx, EDGAR_TICKERS_URL, "company_tickers.json");
      const parsed = parseEdgarTickers(json.body);
      if (!this.ctx.fixture && parsed.filers.length < MIN_LIVE_EDGAR_FILERS) {
        throw new Error(`EDGAR company_tickers.json parsed into only ${parsed.filers.length} filers — format drift suspected`);
      }
      return {
        sourceId: this.id,
        downloads: [json.download],
        entries: [],
        addresses: [],
        filers: parsed.filers,
        stats: { ...emptyStats(), filers: parsed.filers.length, malformedRows: parsed.malformedRows },
      };
    });
  }
}

/** All real sources over one fetch port (cache-aware when configured), in panel order. */
export function realSources(ctx: ListFetchContext): ListSourcePort[] {
  return [
    new OfacSdnSource(ctx),
    new UnConsolidatedSource(ctx),
    new EuConsolidatedSource(ctx),
    new UkHmtSource(ctx),
    new OpenSanctionsPepSource(ctx),
    new SecEdgarSource(ctx),
  ];
}

/**
 * Startup warm hook: parse every source once so the FIRST user request hits
 * the in-process memo instead of paying the cold download+parse (the PEP list
 * alone is ~219 MB / ~2M entries). Fire-and-forget friendly — a source that is
 * cold or unreachable simply degrades to a per-request gap, so warming never
 * throws. Returns the per-source outcome for logging.
 */
export async function warmCompliance(
  sources: readonly ListSourcePort[],
): Promise<Array<{ sourceId: SourceId; ok: boolean; error?: string }>> {
  return Promise.all(
    sources.map(async (s) => {
      try {
        await s.load();
        return { sourceId: s.id, ok: true };
      } catch (err) {
        return { sourceId: s.id, ok: false, error: (err as Error).message };
      }
    }),
  );
}

// ---------------------------------------------------------------------------
// Fixtures — small realistic excerpts served through FakeAttestedFetch, so
// fixture-mode runs exercise the same parse + attestation path for real.
// ---------------------------------------------------------------------------

export const FIXTURE_SDN_CSV = [
  `2306,"AEROCARIBBEAN AIRLINES","-0-","CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"-0-"`,
  `30393,"LAZARUS GROUP","Entity","DPRK3",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Secondary sanctions risk: North Korea Sanctions Regulations; Digital Currency Address - XBT 1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE; alt. Digital Currency Address - XBT 1G9CKRHA3mx22DoT1QyNYrh85VSQ19Y1em."`,
  `36235,"EXAMPLESKI, Ivan Petrovich","individual","SDGT",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 01 Jan 1980; Digital Currency Address - ETH 0x098B716B8Aaf21512996dC57EB0615e2383E2f96."`,
  `44100,"OCEANIC FREIGHT SOLUTIONS LLC","Entity","IRAN-EO13902",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Registered in a third country."`,
].join("\r\n");

export const FIXTURE_ALT_CSV = [
  `30393,1,"aka","LABYRINTH CHOLLIMA","-0-"`,
  `30393,2,"aka","HIDDEN COBRA","-0-"`,
  `36235,3,"aka","EXAMPLESKI, Ivan","Digital Currency Address - XBT bc1qexamplefixture000000000000000000000"`,
].join("\r\n");

export const FIXTURE_UN_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CONSOLIDATED_LIST>
  <INDIVIDUALS>
    <INDIVIDUAL>
      <DATAID>6908555</DATAID>
      <FIRST_NAME>RI</FIRST_NAME>
      <SECOND_NAME>WON HO</SECOND_NAME>
      <UN_LIST_TYPE>DPRK</UN_LIST_TYPE>
      <REFERENCE_NUMBER>KPi.033</REFERENCE_NUMBER>
      <INDIVIDUAL_ALIAS>
        <QUALITY>Good</QUALITY>
        <ALIAS_NAME>Ri Won-ho</ALIAS_NAME>
      </INDIVIDUAL_ALIAS>
    </INDIVIDUAL>
  </INDIVIDUALS>
  <ENTITIES>
    <ENTITY>
      <DATAID>6908443</DATAID>
      <FIRST_NAME>KOREA MINING DEVELOPMENT TRADING CORPORATION</FIRST_NAME>
      <UN_LIST_TYPE>DPRK</UN_LIST_TYPE>
      <REFERENCE_NUMBER>KPe.001</REFERENCE_NUMBER>
      <ENTITY_ALIAS>
        <QUALITY>Good</QUALITY>
        <ALIAS_NAME>KOMID</ALIAS_NAME>
      </ENTITY_ALIAS>
      <ENTITY_ALIAS>
        <QUALITY>Good</QUALITY>
        <ALIAS_NAME>CHANGGWANG SINYONG CORPORATION</ALIAS_NAME>
      </ENTITY_ALIAS>
    </ENTITY>
    <ENTITY>
      <DATAID>6908600</DATAID>
      <FIRST_NAME>LAZARUS GROUP</FIRST_NAME>
      <UN_LIST_TYPE>DPRK</UN_LIST_TYPE>
      <REFERENCE_NUMBER>KPe.099</REFERENCE_NUMBER>
    </ENTITY>
  </ENTITIES>
</CONSOLIDATED_LIST>
`;

export const FIXTURE_EDGAR_JSON = JSON.stringify({
  "0": { cik_str: 1679788, ticker: "COIN", title: "Coinbase Global, Inc." },
  "1": { cik_str: 320193, ticker: "AAPL", title: "Apple Inc." },
  "2": { cik_str: 1318605, ticker: "TSLA", title: "Tesla, Inc." },
});

/** EU FSD v1.1 excerpt: names in ATTRIBUTES; Lazarus appears here too. */
export const FIXTURE_EU_XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<export xmlns="http://eu.europa.ec/fpi/fsd/export" generationDate="2026-06-05T15:51:25.849+02:00" globalFileId="182848">
  <sanctionEntity euReferenceNumber="EU.9999.1" logicalId="900001">
    <regulation regulationType="regulation" programme="DPRK" numberTitle="2024/999" logicalId="700001"/>
    <subjectType code="enterprise" classificationCode="E"/>
    <nameAlias wholeName="LAZARUS GROUP" strong="true" regulationLanguage="en" logicalId="900011"/>
    <nameAlias wholeName="APT38" strong="true" regulationLanguage="en" logicalId="900012"/>
  </sanctionEntity>
  <sanctionEntity euReferenceNumber="EU.9999.2" logicalId="900002">
    <regulation regulationType="regulation" programme="SYR" numberTitle="2024/998" logicalId="700002"/>
    <subjectType code="person" classificationCode="P"/>
    <nameAlias firstName="Ivan" middleName="" lastName="Examplevich" wholeName="Ivan Examplevich" strong="true" regulationLanguage="en" logicalId="900021"/>
    <nameAlias wholeName="Ivan Examplevic" strong="false" regulationLanguage="en" logicalId="900022"/>
  </sanctionEntity>
</export>
`;

/** UK OFSI ConList.csv excerpt (2022 format): preamble + header + grouped rows. */
export const FIXTURE_UK_CSV = [
  `Last Updated,05/06/2026`,
  `Name 6,Name 1,Name 2,Name 3,Name 4,Name 5,Title,Group Type,Alias Type,Regime,Group ID`,
  `,LAZARUS GROUP,,,,,,Entity,Primary name variation,Cyber (Global),90001`,
  `,APT38,,,,,,Entity,AKA,Cyber (Global),90001`,
  `EXAMPLEVICH,Ivan,,,,,Mr,Individual,Primary name variation,Syria,90002`,
  `EXAMPLEVIC,Ivan,,,,,Mr,Individual,AKA,Syria,90002`,
].join("\r\n");

/**
 * OpenSanctions PEP "simple" CSV excerpt (AGGREGATOR). Jens Stoltenberg is a
 * clear (non-sanctioned) PEP used by the demo; the second row exercises a
 * ";"-separated alias and a distinct sub-dataset provenance.
 */
export const FIXTURE_PEP_CSV = [
  `"id","schema","name","aliases","birth_date","countries","dataset"`,
  `"NK-PEPFIX01","Person","Jens Stoltenberg","Stoltenberg, Jens","1959-03-16","no","Norway State Officials"`,
  `"NK-PEPFIX02","Person","Amara Diallo Kone","Kone, Amara;Amara D. Kone","1970-01-01","ml","Mali National Assembly"`,
].join("\r\n");

/**
 * Fixture-backed versions of all three sources: the same adapters, fed by a
 * FakeAttestedFetch routing the primary URLs to the canned excerpts above.
 * Downloads are labeled mode "fixture" and carry REAL (mock-DAHR) signatures.
 */
export function fixtureSources(): ListSourcePort[] {
  const port = new FakeAttestedFetch([
    ["exports/SDN.CSV", { status: 200, body: FIXTURE_SDN_CSV }],
    ["exports/ALT.CSV", { status: 200, body: FIXTURE_ALT_CSV }],
    ["scsanctions.un.org", { status: 200, body: FIXTURE_UN_XML }],
    ["xmlFullSanctionsList", { status: 200, body: FIXTURE_EU_XML }],
    ["ConList.csv", { status: 200, body: FIXTURE_UK_CSV }],
    ["targets.simple.csv", { status: 200, body: FIXTURE_PEP_CSV }],
    ["company_tickers.json", { status: 200, body: FIXTURE_EDGAR_JSON }],
  ]);
  const ctx: ListFetchContext = { port, fixture: true };
  return realSources(ctx);
}
