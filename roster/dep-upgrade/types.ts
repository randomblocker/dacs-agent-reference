/**
 * Dependency-Upgrade Agent — types and ports.
 *
 * The agent turns CVE/version intel into verified, green PRs against a target
 * repo working copy. Pure planning logic sits between three injected ports:
 *
 *  - RegistryPort   — npm packuments + the bulk security-advisory endpoint
 *                     (real fetch adapter, or canned data for tests/offline).
 *  - CommandRunner  — how "verify" happens (`npm install` + `npm test` in the
 *                     target dir for real; scripted exit codes in tests).
 *  - GitHubPort     — PR delivery. Mock adapter only today (in-memory, same
 *                     api.github.com URL shapes as src/github.ts); going real
 *                     is an adapter swap that needs an authed `gh`/token.
 *
 * No DACS lifecycle wiring, no credentials, no framework — node builtins only.
 */

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

export type DepSection = "dependencies" | "devDependencies";

export interface DepEntry {
  name: string;
  /** Declared range straight out of package.json (e.g. `^4.17.20`). */
  range: string;
  section: DepSection;
  /**
   * Concrete installed version from package-lock.json, when a lockfile is
   * present and has an entry. Lockfile-less repos leave this undefined —
   * the planner then resolves the range against the registry's version list.
   */
  installedVersion?: string;
}

export interface DepInventory {
  /** Absolute path of the working copy the inventory was read from. */
  dir: string;
  packageName: string;
  deps: DepEntry[];
  hadLockfile: boolean;
}

// ---------------------------------------------------------------------------
// Registry port (packuments + advisories)
// ---------------------------------------------------------------------------

export interface Packument {
  name: string;
  /** `dist-tags.latest`. */
  latest: string;
  /** Every published version string, unsorted. */
  versions: string[];
}

export interface Advisory {
  /** GHSA id (or numeric id rendered as string). */
  id: string;
  severity: "low" | "moderate" | "high" | "critical" | "unknown";
  title: string;
  url: string;
  /** node-semver range of affected versions, e.g. `<4.17.21`. */
  vulnerableVersions: string;
}

export interface RegistryPort {
  getPackument(name: string): Promise<Packument>;
  /**
   * Bulk advisory lookup — mirrors
   * `POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk`
   * with body `{ "<pkg>": ["<version>", ...] }`.
   */
  getAdvisories(query: Record<string, string[]>): Promise<Map<string, Advisory[]>>;
}

// ---------------------------------------------------------------------------
// Upgrade plan
// ---------------------------------------------------------------------------

export type UpgradeKind = "security" | "outdated" | "next-major";

export interface UpgradeItem {
  name: string;
  section: DepSection;
  kind: UpgradeKind;
  currentVersion: string;
  currentRange: string;
  targetVersion: string;
  /** New declared range, preserving the ^/~ style of the current one. */
  newRange: string;
  /** True when the fix forces a major-version escalation. */
  breaking: boolean;
  /** Advisories this upgrade clears (empty for pure maintenance bumps). */
  advisories: Advisory[];
  rationale: string;
}

export interface UnactionableDep {
  name: string;
  reason: string;
}

export interface UpgradePlan {
  items: UpgradeItem[];
  /** Vulnerable deps no published version can clear, unresolvable ranges, etc. */
  unactionable: UnactionableDep[];
}

// ---------------------------------------------------------------------------
// Verify (command runner port)
// ---------------------------------------------------------------------------

export interface CommandResult {
  /** Human-readable command, e.g. `npm install`. */
  command: string;
  exitCode: number;
  /** Combined stdout+stderr. */
  output: string;
}

export interface CommandRunner {
  run(cmd: string, args: string[], cwd: string): Promise<CommandResult>;
}

export interface ItemResult {
  item: UpgradeItem;
  /** True when the item survived verification and stays in package.json. */
  applied: boolean;
  /** Every verify command run for this item, in order, with exit codes. */
  verify: CommandResult[];
  /** Which command went red (unset when applied). */
  failedAt?: string;
  /** Tail of the failing command's output (unset when applied). */
  outputTail?: string;
}

export interface ApplyVerifyResult {
  results: ItemResult[];
  /** Final package.json text after all green items (reverts already undone). */
  finalPackageJson: string;
  /** True when at least one item was applied and kept. */
  changed: boolean;
}

// ---------------------------------------------------------------------------
// GitHub port (PR delivery)
// ---------------------------------------------------------------------------

export interface RepoRef {
  owner: string;
  repo: string;
}

export interface GitHubPort {
  getRepo(ref: RepoRef): Promise<{ full_name: string; default_branch: string }>;
  createBranch(ref: RepoRef, branch: string, fromBranch: string): Promise<void>;
  commitFiles(
    ref: RepoRef,
    branch: string,
    message: string,
    files: Array<{ path: string; content: string }>,
  ): Promise<{ sha: string }>;
  openPR(
    ref: RepoRef,
    params: { head: string; base: string; title: string; body: string },
  ): Promise<{ number: number; html_url: string }>;
}

// ---------------------------------------------------------------------------
// Agent config + report
// ---------------------------------------------------------------------------

export interface DepUpgradeConfig {
  /** Also propose next-major bumps for merely-outdated deps (default false). */
  proposeNextMajor?: boolean;
}

export interface DepUpgradeReport {
  inventory: DepInventory;
  plan: UpgradePlan;
  results: ItemResult[];
  prBody: string;
  /** Null when nothing survived verification (no PR is opened). */
  pr: { number: number; html_url: string; branch: string } | null;
}
