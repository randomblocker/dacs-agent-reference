/**
 * Inventory — direct dependencies of a target working copy.
 *
 * Reads package.json (required) and package-lock.json (optional; v1 and
 * v2/v3 formats). Lockfile-less repos are fully supported: entries simply
 * carry no `installedVersion` and the planner resolves the declared range
 * against the registry's version list instead.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { DepEntry, DepInventory, DepSection } from "./types.js";

interface PkgJsonShape {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface LockShape {
  lockfileVersion?: number;
  /** v2/v3: keys like "node_modules/<name>". */
  packages?: Record<string, { version?: string }>;
  /** v1: direct map of name → { version }. */
  dependencies?: Record<string, { version?: string }>;
}

/** Pure parser — testable without touching the filesystem. */
export function parseInventory(dir: string, pkgJsonText: string, lockText?: string): DepInventory {
  let pkg: PkgJsonShape;
  try {
    pkg = JSON.parse(pkgJsonText) as PkgJsonShape;
  } catch (err) {
    throw new Error(`inventory: package.json is not valid JSON (${(err as Error).message})`);
  }

  let lock: LockShape | undefined;
  if (lockText !== undefined) {
    try {
      lock = JSON.parse(lockText) as LockShape;
    } catch {
      lock = undefined; // a corrupt lockfile degrades to lockfile-less behaviour
    }
  }

  const installedVersion = (name: string): string | undefined => {
    if (!lock) return undefined;
    const fromV2 = lock.packages?.[`node_modules/${name}`]?.version;
    if (fromV2) return fromV2;
    return lock.dependencies?.[name]?.version;
  };

  const deps: DepEntry[] = [];
  const sections: Array<[DepSection, Record<string, string> | undefined]> = [
    ["dependencies", pkg.dependencies],
    ["devDependencies", pkg.devDependencies],
  ];
  for (const [section, map] of sections) {
    for (const [name, range] of Object.entries(map ?? {})) {
      deps.push({ name, range, section, installedVersion: installedVersion(name) });
    }
  }

  return {
    dir,
    packageName: pkg.name ?? "(unnamed)",
    deps,
    hadLockfile: lock !== undefined,
  };
}

/** Read the inventory from a working copy on disk. */
export async function readInventory(dir: string): Promise<DepInventory> {
  const pkgJsonText = await readFile(join(dir, "package.json"), "utf8");
  let lockText: string | undefined;
  try {
    lockText = await readFile(join(dir, "package-lock.json"), "utf8");
  } catch {
    lockText = undefined;
  }
  return parseInventory(dir, pkgJsonText, lockText);
}
