/**
 * Input-side injection scanner — the mirror of the output-side guard.
 *
 * `scan.ts` is a COST pre-scanner (KLOC/tooling). This module is the SECURITY
 * pre-scanner for the OTHER direction: any untrusted counterparty free-text
 * (`NegotiationMove.rationale`) that would flow into an LLM prompt is passed
 * through here FIRST. It is the input-side twin of the deterministic settlement
 * guard (`terms.ts#sellerMaySettle`/`buyerMaySettle`): the guard makes the
 * NUMBER binding unbreakable no matter what the model does; this makes the
 * PROMPT itself resistant to a counterparty smuggling instructions into its
 * rationale to steer the model in the first place.
 *
 * It is a deterministic heuristic scanner in the SafeAgent mould
 * (see the SafeAgent §Layer-1 categories): role-confusion, instruction
 * injection, price/tier directives, and exfiltration asks. It NEVER makes a
 * money decision (the guard does that) — it detects, flags, and NEUTRALIZES
 * the text so the model reads sanitized data, and returns the flags so the
 * caller can LOG the decision (never silent).
 *
 * Two-layer defence, restated: even if this scanner missed a novel jailbreak
 * AND the model were fully swayed, the settlement guard still refuses any
 * out-of-bounds move. This layer reduces the odds the model is swayed at all;
 * the guard is why being swayed cannot settle a bad deal.
 */

/** The heuristic categories the scanner recognises (SafeAgent Layer-1 mould). */
export type InjectionCategory =
  | "role-confusion"
  | "instruction-injection"
  | "price-tier-directive"
  | "exfiltration"
  | "urgent-pressure";

/** One matched pattern: its category and the exact span it fired on. */
export interface InjectionHit {
  category: InjectionCategory;
  /** The literal text that matched (bounded) — for the audit log, not the prompt. */
  match: string;
}

export interface InjectionScan {
  /** True iff nothing suspicious was found. */
  clean: boolean;
  /** Distinct categories that fired, sorted — the decision record. */
  flags: InjectionCategory[];
  /** Every individual match (for logging). */
  hits: InjectionHit[];
  /** The text with every matched span replaced by a redaction marker. */
  sanitized: string;
}

interface Rule {
  category: InjectionCategory;
  re: RegExp;
}

/**
 * The rule table. Every regex is GLOBAL + case-insensitive so `replace` can
 * neutralize every occurrence. Kept deliberately conservative and specific to
 * avoid shredding legitimate haggling rationale ("conceding to 9 for deep").
 */
const RULES: Rule[] = [
  // --- role-confusion: pretending to be system/another turn -----------------
  { category: "role-confusion", re: /\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|messages?|prompts?|context)\b/gi },
  { category: "role-confusion", re: /\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier|foregoing)\b/gi },
  { category: "role-confusion", re: /\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|new\s+instructions?\s*:|new\s+system\s+prompt)\b/gi },
  { category: "role-confusion", re: /\[\/?INST\]/gi },
  { category: "role-confusion", re: /<\|[^|>]{0,40}\|>/g },
  { category: "role-confusion", re: /(?:^|\n|\s)(?:system|assistant|developer)\s*:/gi },
  { category: "role-confusion", re: /\b(?:###\s*)?(?:system|instruction)\s+(?:override|prompt)\b/gi },

  // --- price/tier directive: tell the model to change the deal --------------
  { category: "price-tier-directive", re: /\b(?:set|change|make|lower|raise|drop|reduce|adjust|update)\s+(?:the\s+|your\s+)?(?:price|floor|budget|tier|quote|offer)\b(?:\s+\w+){0,4}?\s*(?:to|=|at)\s*[\d$]/gi },
  { category: "price-tier-directive", re: /\b(?:accept|agree\s+to|settle\s+(?:for|at)|approve)\s+(?:any|all|whatever|this)\b(?:\s+\w+){0,3}?\s*(?:price|terms|offer|deal)\b/gi },
  { category: "price-tier-directive", re: /\b(?:price|floor|budget)\s*(?:=|:)\s*\d+(?:\.\d+)?\b/gi },
  { category: "price-tier-directive", re: /\b(?:you\s+must|please)\s+(?:accept|agree|settle|approve)\b/gi },

  // --- exfiltration: pull out the private brief / secrets --------------------
  { category: "exfiltration", re: /\b(?:reveal|show|share|print|disclose|expose|leak|tell\s+me|what(?:'?s|\s+is)\s+your)\b(?:\s+\w+){0,6}?\s*(?:floor|budget|reservation|private|secret|system\s+prompt|instructions?|mnemonic|seed\s+phrase|api\s+key|walk[-\s]?away)\b/gi },
  { category: "exfiltration", re: /\brepeat\s+(?:your\s+|the\s+)?(?:system\s+prompt|instructions?|floor|budget)\b/gi },

  // --- urgent-pressure: manufactured urgency to short-circuit deliberation ---
  { category: "urgent-pressure", re: /\b(?:act\s+now|right\s+now\s+or|immediately\s+or\s+(?:lose|forfeit)|last\s+chance\s+forever|this\s+will\s+expire\s+in\s+seconds)\b/gi },
];

/** Redaction marker substituted for a neutralized span (visible, non-silent). */
export function redactionMarker(category: InjectionCategory): string {
  return `[redacted:${category}]`;
}

/**
 * Scan untrusted text for injection heuristics. Deterministic and side-effect
 * free. Returns the flags (for logging) and a sanitized copy safe to embed.
 */
export function scanForInjection(text: string): InjectionScan {
  if (typeof text !== "string" || text.length === 0) {
    return { clean: true, flags: [], hits: [], sanitized: "" };
  }
  const hits: InjectionHit[] = [];
  let sanitized = text;

  for (const rule of RULES) {
    // Reset lastIndex — the regexes are global and reused across calls.
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(text)) !== null) {
      hits.push({ category: rule.category, match: m[0].slice(0, 120) });
      if (m[0].length === 0) rule.re.lastIndex++; // guard against zero-width loops
    }
    rule.re.lastIndex = 0;
    sanitized = sanitized.replace(rule.re, redactionMarker(rule.category));
  }

  const flags = [...new Set(hits.map((h) => h.category))].sort();
  return { clean: hits.length === 0, flags, hits, sanitized };
}

/**
 * Wrap untrusted text in explicit delimiters AND neutralize any injection,
 * producing a prompt-safe block. This is what the prompt builders embed instead
 * of the raw counterparty rationale: the model is told the boundary and that the
 * content is data, and any detected steering is stripped before it reaches the
 * model. Returns the block plus the scan (so the caller logs the decision).
 */
export function fenceUntrusted(text: string): { block: string; scan: InjectionScan } {
  const scan = scanForInjection(text);
  const note = scan.clean
    ? ""
    : ` [!] ${scan.hits.length} injection pattern(s) neutralized: ${scan.flags.join(", ")}`;
  const block = `«untrusted-counterparty-text${note}» ${scan.sanitized} «/untrusted»`;
  return { block, scan };
}
