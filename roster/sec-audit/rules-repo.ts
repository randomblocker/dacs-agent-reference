/**
 * Repo rules — a deterministic rule table over source lines plus a small
 * filename table for files that should never be committed at all.
 *
 * False-positive hygiene, cheap and explicit:
 *  - dangerous-code rules skip comment lines (`skipComments: true`); secret
 *    rules do NOT — a credential in a comment is still a leak;
 *  - the generic secret-assignment rule requires a high-entropy, mixed
 *    character-class literal and rejects obvious placeholders
 *    (example/changeme/xxx/${…}/process.env…);
 *  - the plaintext-http rule ignores localhost/loopback and XML-namespace
 *    hosts (www.w3.org, schemas.*).
 *
 * Suppression (`// audit-ok <ruleId>` on the hit line or the line above) is
 * applied by the scanner, not here — rules stay pure detectors.
 */
import type { RawHit, RuleMeta, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Rule shape
// ---------------------------------------------------------------------------

export interface RepoLineRule extends RuleMeta {
  /** True = comment lines are not scanned by this rule. */
  skipComments: boolean;
  /** Return a rationale when the line matches, null otherwise. */
  detect(line: string): string | null;
}

export interface RepoFileRule extends RuleMeta {
  /** Matches on the relative path (posix separators). */
  matchesPath(relPath: string): boolean;
  rationale(relPath: string): string;
}

/** Cheap comment detection: the line *starts* as a comment. */
export function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return (
    t.startsWith("//") ||
    t.startsWith("#") ||
    t.startsWith("*") ||
    t.startsWith("/*") ||
    t.startsWith("<!--")
  );
}

// ---------------------------------------------------------------------------
// Entropy + placeholder helpers (secret-assignment)
// ---------------------------------------------------------------------------

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const PLACEHOLDER = /example|sample|your[-_ ]|changeme|change[-_ ]me|placeholder|dummy|fixme|todo|redacted|xxx|<[^>]*>|\$\{|process\.env/i;

/** Mixed character classes + entropy: what a real secret literal looks like. */
export function looksLikeSecretLiteral(literal: string): boolean {
  if (literal.length < 16) return false;
  if (PLACEHOLDER.test(literal)) return false;
  const hasLower = /[a-z]/.test(literal);
  const hasUpperOrDigit = /[A-Z0-9]/.test(literal);
  if (!(hasLower && hasUpperOrDigit)) return false;
  return shannonEntropy(literal) >= 3.2;
}

// ---------------------------------------------------------------------------
// Line-rule table
// ---------------------------------------------------------------------------

const SECRET_ASSIGN_RE =
  /(?:api[_-]?key|apikey|token|passwd|password|secret|private[_-]?key|access[_-]?key|client[_-]?secret)\s*["']?\s*[:=]\s*["']([^"']{8,})["']/i;

const MNEMONIC_RE = /["']([a-z]{3,8}(?: [a-z]{3,8}){11}(?:(?: [a-z]{3,8}){12})?)["']/;

const HTTP_URL_RE = /["'`]http:\/\/([^\s"'`]+)/;

export const REPO_LINE_RULES: RepoLineRule[] = [
  {
    id: "secret-aws-key",
    severity: "critical",
    description: "AWS access key id committed to source",
    skipComments: false,
    detect: (line) =>
      /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/.test(line)
        ? "The literal matches the AWS access-key-id format (AKIA/ASIA + 16 chars). Committed cloud keys must be revoked and rotated immediately."
        : null,
  },
  {
    id: "secret-assignment",
    severity: "high",
    description: "High-entropy secret literal assigned to a credential-named variable",
    skipComments: false,
    detect: (line) => {
      const m = SECRET_ASSIGN_RE.exec(line);
      if (!m || !looksLikeSecretLiteral(m[1])) return null;
      return "A credential-named field is assigned a high-entropy string literal — this looks like a real secret hardcoded in source. Move it to an environment variable or secret store and rotate it.";
    },
  },
  {
    id: "secret-pem-block",
    severity: "critical",
    description: "PEM private-key block committed to source",
    skipComments: false,
    detect: (line) =>
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/.test(line)
        ? "A PEM private-key header is present. Private keys must never be committed; revoke and rotate this keypair."
        : null,
  },
  {
    id: "secret-mnemonic",
    severity: "high",
    description: "Mnemonic-looking 12/24-word phrase committed to source",
    skipComments: false,
    detect: (line) =>
      MNEMONIC_RE.test(line)
        ? "A quoted phrase of exactly 12 or 24 lowercase words looks like a BIP-39 wallet mnemonic. Any funds controlled by this phrase should be treated as compromised."
        : null,
  },
  {
    id: "code-eval",
    severity: "high",
    description: "eval()/new Function() — dynamic code execution",
    skipComments: true,
    detect: (line) =>
      /\beval\s*\(/.test(line) || /\bnew\s+Function\s*\(/.test(line)
        ? "eval()/new Function() executes arbitrary strings as code; with any attacker-influenced input this is remote code execution."
        : null,
  },
  {
    id: "code-exec-interpolation",
    severity: "high",
    description: "child_process exec with template interpolation (command injection)",
    skipComments: true,
    detect: (line) =>
      /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*`[^`]*\$\{/.test(line)
        ? "A shell command is built by template interpolation — attacker-influenced input becomes shell syntax (command injection). Use execFile with an argument array."
        : null,
  },
  {
    id: "code-exec-dynamic-argument",
    severity: "high",
    description: "child_process shell execution with a dynamic command argument",
    skipComments: true,
    detect: (line) => {
      // exec/execSync always invoke a shell. A non-literal first argument is
      // therefore a command-injection boundary even when interpolation occurs
      // on an earlier line (`const command = req.query.cmd; exec(command)`).
      // Static quoted commands remain outside this rule; execFile/spawn are
      // deliberately excluded because their argument-array semantics differ.
      const call = /\b(?:exec|execSync)\s*\(\s*([^,)]*)/.exec(line);
      if (!call) return null;
      const argument = call[1]?.trim() ?? "";
      if (!argument || /^(?:["'][^"']*["']|`[^`]*`)$/.test(argument)) return null;
      return "A shell command is supplied through a dynamic expression. If any part comes from a request, URL, file, environment, or model output, an attacker can inject shell syntax. Use execFile with a fixed executable and validated argument array.";
    },
  },
  {
    id: "code-http-url",
    severity: "medium",
    description: "Plaintext http:// endpoint in source (no TLS)",
    skipComments: true,
    detect: (line) => {
      const m = HTTP_URL_RE.exec(line);
      if (!m) return null;
      const rest = m[1];
      if (/^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])/.test(rest)) return null;
      if (/^(?:www\.w3\.org|schemas\.)/.test(rest)) return null; // XML namespaces, not endpoints
      return "A non-TLS http:// endpoint is used — traffic (including any credentials) is readable and modifiable in transit. Use https://.";
    },
  },
  {
    id: "crypto-weak-hash",
    severity: "medium",
    description: "MD5/SHA-1 used via the crypto API",
    skipComments: true,
    detect: (line) =>
      /create(?:Hash|Hmac)\s*\(\s*["'](?:md5|sha1)["']/i.test(line)
        ? "MD5 and SHA-1 are collision-broken; in any security context (signatures, integrity, password hashing) they are unsafe. Use SHA-256 or better."
        : null,
  },
  {
    id: "crypto-math-random-token",
    severity: "high",
    description: "Math.random() used to derive a secret/token",
    skipComments: true,
    detect: (line) =>
      /Math\.random\s*\(/.test(line) &&
      /token|secret|password|nonce|session|auth|otp|api[_-]?key|credential/i.test(line)
        ? "Math.random() is not cryptographically secure — tokens derived from it are predictable. Use crypto.randomBytes/randomUUID."
        : null,
  },
  {
    id: "tls-verification-disabled",
    severity: "high",
    description: "TLS certificate verification disabled",
    skipComments: true,
    detect: (line) =>
      /rejectUnauthorized\s*:\s*false/.test(line) ||
      /NODE_TLS_REJECT_UNAUTHORIZED\s*(?:[:=]|\]\s*=)\s*["']?0["']?/.test(line)
        ? "Certificate verification is disabled, so any man-in-the-middle can impersonate the server. Never ship this outside a hermetic test."
        : null,
  },
];

// ---------------------------------------------------------------------------
// Filename-rule table
// ---------------------------------------------------------------------------

function baseName(relPath: string): string {
  const i = relPath.lastIndexOf("/");
  return i === -1 ? relPath : relPath.slice(i + 1);
}

export const REPO_FILE_RULES: RepoFileRule[] = [
  {
    id: "secret-file-committed",
    severity: "high",
    description: "Secret-bearing file committed (.env / id_rsa / *.pem)",
    matchesPath: (relPath) => {
      const base = baseName(relPath);
      if (/^\.env(\..+)?$/.test(base) && !/\.(example|sample|template|dist)$/.test(base)) return true;
      if (base === "id_rsa" || base === "id_ed25519" || base === "id_ecdsa") return true;
      return base.endsWith(".pem");
    },
    rationale: (relPath) =>
      `"${relPath}" is a secret-bearing file type (.env / SSH private key / PEM) and should not be committed. Add it to .gitignore and rotate anything it contains.`,
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export const REPO_RULE_TABLE: RuleMeta[] = [
  ...REPO_LINE_RULES.map(({ id, severity, description }) => ({ id, severity, description })),
  ...REPO_FILE_RULES.map(({ id, severity, description }) => ({ id, severity, description })),
];

function hit(rule: RuleMeta, file: string, line: number, excerpt: string, rationale: string): RawHit {
  return { ruleId: rule.id, severity: rule.severity as Severity, file, line, excerpt, rationale };
}

/** Run every line rule over a file's text (1-based line numbers). */
export function runRepoLineRules(relPath: string, text: string): RawHit[] {
  const hits: RawHit[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const comment = isCommentLine(line);
    for (const rule of REPO_LINE_RULES) {
      if (rule.skipComments && comment) continue;
      const rationale = rule.detect(line);
      if (rationale) hits.push(hit(rule, relPath, i + 1, line.trim(), rationale));
    }
  }
  return hits;
}

/** Run the filename rules (hits land on line 1 with the path as excerpt). */
export function runRepoFileRules(relPath: string): RawHit[] {
  const hits: RawHit[] = [];
  for (const rule of REPO_FILE_RULES) {
    if (rule.matchesPath(relPath)) hits.push(hit(rule, relPath, 1, relPath, rule.rationale(relPath)));
  }
  return hits;
}
