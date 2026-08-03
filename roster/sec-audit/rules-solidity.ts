/**
 * Solidity heuristics over .sol files. These are HEURISTIC static checks —
 * they read blanked-out source (comments and string literals replaced by
 * spaces, newlines preserved so line numbers survive) and a lightweight
 * brace-matched function map. No compiler, no AST; the rationale strings
 * say "review" rather than "exploit" accordingly.
 *
 * Rules:
 *  - sol-tx-origin              tx.origin used (authentication anti-pattern)
 *  - sol-unchecked-call         low-level .call/.send return value unused
 *  - sol-delegatecall-variable  delegatecall to a variable target
 *  - sol-selfdestruct           selfdestruct present
 *  - sol-reentrancy             external .call before a later state write
 *                               in the same function body
 *  - sol-floating-pragma        pragma solidity ^…
 *  - sol-timestamp-condition    block.timestamp inside require/if
 *  - sol-missing-access-control public/external function writes critical
 *                               state (owner=… / balances[not-msg.sender])
 *                               with no onlyOwner-like modifier or
 *                               msg.sender check
 */
import type { RawHit, RuleMeta, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Source preparation
// ---------------------------------------------------------------------------

/**
 * Replace // and slash-star comments and string-literal contents with spaces,
 * preserving newlines and column positions, so detectors don't fire on prose
 * and line numbers stay true to the original file.
 */
export function blankCommentsAndStrings(source: string): string {
  const out = source.split("");
  type State = "code" | "line-comment" | "block-comment" | "dquote" | "squote";
  let state: State = "code";
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    const next = source[i + 1];
    switch (state) {
      case "code":
        if (c === "/" && next === "/") {
          state = "line-comment";
          out[i] = " ";
        } else if (c === "/" && next === "*") {
          state = "block-comment";
          out[i] = " ";
        } else if (c === '"') {
          state = "dquote";
        } else if (c === "'") {
          state = "squote";
        }
        break;
      case "line-comment":
        if (c === "\n") state = "code";
        else out[i] = " ";
        break;
      case "block-comment":
        if (c === "*" && next === "/") {
          out[i] = " ";
          out[i + 1] = " ";
          i += 1;
          state = "code";
        } else if (c !== "\n") {
          out[i] = " ";
        }
        break;
      case "dquote":
        if (c === "\\") {
          out[i] = " ";
          if (next !== undefined && next !== "\n") {
            out[i + 1] = " ";
            i += 1;
          }
        } else if (c === '"') {
          state = "code";
        } else if (c !== "\n") {
          out[i] = " ";
        }
        break;
      case "squote":
        if (c === "\\") {
          out[i] = " ";
          if (next !== undefined && next !== "\n") {
            out[i + 1] = " ";
            i += 1;
          }
        } else if (c === "'") {
          state = "code";
        } else if (c !== "\n") {
          out[i] = " ";
        }
        break;
    }
  }
  return out.join("");
}

export interface SolFunction {
  name: string;
  /** Declaration text from `function`/`constructor` to the opening brace. */
  header: string;
  /** 1-based line of the declaration. */
  headerLine: number;
  /** Body text between (not including) the braces. */
  body: string;
  /** 1-based line the body starts on (the opening-brace line). */
  bodyStartLine: number;
}

function lineOfIndex(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) if (source[i] === "\n") line += 1;
  return line;
}

/** Brace-matched function map over blanked source. Bodiless declarations are skipped. */
export function extractFunctions(blanked: string): SolFunction[] {
  const fns: SolFunction[] = [];
  const decl = /\b(function\s+(\w+)|constructor)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = decl.exec(blanked)) !== null) {
    const name = m[2] ?? "constructor";
    const start = m.index;
    // Find the header end: the first `{` or `;` after the declaration.
    let i = start;
    while (i < blanked.length && blanked[i] !== "{" && blanked[i] !== ";") i += 1;
    if (i >= blanked.length || blanked[i] === ";") continue; // interface/abstract — no body
    const braceOpen = i;
    let depth = 0;
    let end = -1;
    for (let j = braceOpen; j < blanked.length; j++) {
      if (blanked[j] === "{") depth += 1;
      else if (blanked[j] === "}") {
        depth -= 1;
        if (depth === 0) {
          end = j;
          break;
        }
      }
    }
    if (end === -1) continue; // unbalanced — skip rather than guess
    fns.push({
      name,
      header: blanked.slice(start, braceOpen),
      headerLine: lineOfIndex(blanked, start),
      body: blanked.slice(braceOpen + 1, end),
      bodyStartLine: lineOfIndex(blanked, braceOpen),
    });
  }
  return fns;
}

// ---------------------------------------------------------------------------
// Rule table
// ---------------------------------------------------------------------------

export const SOL_RULE_TABLE: RuleMeta[] = [
  { id: "sol-tx-origin", severity: "high", description: "tx.origin used — authentication anti-pattern" },
  { id: "sol-unchecked-call", severity: "medium", description: "Low-level .call/.send return value unused" },
  { id: "sol-delegatecall-variable", severity: "high", description: "delegatecall to a variable target address" },
  { id: "sol-selfdestruct", severity: "medium", description: "selfdestruct present in contract" },
  { id: "sol-reentrancy", severity: "high", description: "External .call before a later state write (reentrancy shape)" },
  { id: "sol-floating-pragma", severity: "low", description: "Floating pragma (^) — compiler version not pinned" },
  { id: "sol-timestamp-condition", severity: "low", description: "block.timestamp used in a require/if condition" },
  {
    id: "sol-missing-access-control",
    severity: "medium",
    description: "public/external function writes critical state without an access-control modifier",
  },
];

const META = new Map(SOL_RULE_TABLE.map((r) => [r.id, r]));

function solHit(ruleId: string, file: string, line: number, excerpt: string, rationale: string): RawHit {
  const meta = META.get(ruleId);
  if (!meta) throw new Error(`unknown solidity rule ${ruleId}`);
  return { ruleId, severity: meta.severity as Severity, file, line, excerpt, rationale };
}

const EXTERNAL_CALL_RE = /\.call\s*[({]/;
const UNCHECKED_CALL_RE = /\.(?:call|send)\s*[({]/;
/** A statement that writes state: `x = …`, `x += …`, `m[k] -= …`, … */
const STATE_WRITE_RE = /^\s*[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s*(?:=(?!=)|\+=|-=|\*=|\|=)/;
const CRITICAL_WRITE_RE = /(?:^|\s)owner\s*=(?!=)|balances\s*\[\s*(?!msg\.sender\s*\])[^\]]+\]\s*(?:=(?!=)|\+=|-=)/;
const ACCESS_MODIFIER_RE = /\bonly[A-Za-z_]\w*|\bauth\b|\badmin(?:Only)?\b|\brequiresAuth\b/i;
const SENDER_CHECK_RE = /require\s*\([^;]*msg\.sender|msg\.sender\s*==|==\s*msg\.sender/;

/**
 * Run every Solidity rule over one file. `originalText` is used only for
 * excerpts (so the reader sees the real line, comments included); all
 * detection runs on the blanked source.
 */
export function runSolidityRules(relPath: string, originalText: string): RawHit[] {
  const hits: RawHit[] = [];
  const blanked = blankCommentsAndStrings(originalText);
  const originalLines = originalText.split("\n");
  const blankedLines = blanked.split("\n");
  const excerptAt = (line1: number): string => (originalLines[line1 - 1] ?? "").trim();

  // Per-line rules over the blanked source.
  for (let i = 0; i < blankedLines.length; i++) {
    const line = blankedLines[i];
    const n = i + 1;

    if (/\bpragma\s+solidity\s+[^;]*\^/.test(line)) {
      hits.push(
        solHit(
          "sol-floating-pragma",
          relPath,
          n,
          excerptAt(n),
          "A floating pragma (^) lets the contract compile under future compiler minors with different semantics/optimizer behavior. Pin an exact version for deployed code.",
        ),
      );
    }
    if (/\btx\.origin\b/.test(line)) {
      hits.push(
        solHit(
          "sol-tx-origin",
          relPath,
          n,
          excerptAt(n),
          "tx.origin identifies the EOA that started the transaction, not the caller — any contract the user interacts with can pass a tx.origin check (classic phishing vector). Use msg.sender.",
        ),
      );
    }
    if (/\bselfdestruct\s*\(/.test(line)) {
      hits.push(
        solHit(
          "sol-selfdestruct",
          relPath,
          n,
          excerptAt(n),
          "selfdestruct removes the contract and force-sends its balance; if reachable by the wrong caller it is a rug primitive. Review who can reach this path.",
        ),
      );
    }
    const dc = /(\w+)\.delegatecall\s*[({]/.exec(line);
    if (dc && dc[1] !== "this" && !/^[A-Z][A-Z0-9_]*$/.test(dc[1])) {
      hits.push(
        solHit(
          "sol-delegatecall-variable",
          relPath,
          n,
          excerptAt(n),
          `delegatecall runs foreign code with THIS contract's storage and balance; the target here ("${dc[1]}") is a variable, so whoever controls it controls the contract. Pin the target or gate who can set it.`,
        ),
      );
    }
    if (/\b(?:require|if)\s*\(/.test(line) && /\bblock\.timestamp\b/.test(line)) {
      hits.push(
        solHit(
          "sol-timestamp-condition",
          relPath,
          n,
          excerptAt(n),
          "block.timestamp is miner/validator-influenceable within a few seconds; conditions that gate value on it can be nudged. Fine for coarse deadlines, unsafe for fine-grained logic.",
        ),
      );
    }
    if (
      UNCHECKED_CALL_RE.test(line) &&
      !/=/.test(line) &&
      !/\brequire\s*\(|\bif\s*\(|\breturn\b|\bbool\b/.test(line)
    ) {
      hits.push(
        solHit(
          "sol-unchecked-call",
          relPath,
          n,
          excerptAt(n),
          ".call/.send report failure via their return value instead of reverting; ignoring it lets a failed transfer pass silently. Capture the success flag and require() it.",
        ),
      );
    }
  }

  // Function-scoped rules.
  for (const fn of extractFunctions(blanked)) {
    const bodyLines = fn.body.split("\n");

    // Reentrancy shape: external .call, then a later state write in the same body.
    let callLine = -1;
    for (let i = 0; i < bodyLines.length; i++) {
      if (callLine === -1 && EXTERNAL_CALL_RE.test(bodyLines[i])) {
        callLine = i;
        continue;
      }
      if (callLine !== -1 && STATE_WRITE_RE.test(bodyLines[i])) {
        const hitLine = fn.bodyStartLine + callLine;
        hits.push(
          solHit(
            "sol-reentrancy",
            relPath,
            hitLine,
            excerptAt(hitLine),
            `function ${fn.name}(): an external .call happens before state is written on line ${fn.bodyStartLine + i} — a reentrant callee sees stale state (checks-effects-interactions violated). Write state first or add a reentrancy guard.`,
          ),
        );
        break;
      }
    }

    // Missing access control on critical-state writers.
    if (fn.name !== "constructor" && /\b(?:public|external)\b/.test(fn.header)) {
      const critical = bodyLines.findIndex((l) => CRITICAL_WRITE_RE.test(l));
      if (critical !== -1 && !ACCESS_MODIFIER_RE.test(fn.header) && !SENDER_CHECK_RE.test(fn.body)) {
        hits.push(
          solHit(
            "sol-missing-access-control",
            relPath,
            fn.headerLine,
            excerptAt(fn.headerLine),
            `function ${fn.name}() is ${/\bexternal\b/.test(fn.header) ? "external" : "public"} and writes critical state (owner/balances) on line ${fn.bodyStartLine + critical}, but carries no onlyOwner-like modifier and no msg.sender check — anyone can call it.`,
          ),
        );
      }
    }
  }

  return hits;
}
