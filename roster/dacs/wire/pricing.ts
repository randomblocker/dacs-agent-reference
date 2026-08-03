/**
 * Fee formatting + usage-based (per-unit) pricing for listing descriptions.
 *
 * Two fee shapes travel through the DACS seller layer (both reuse the Butler's
 * `FeeSchedule`, re-exported below so the wire has one source of truth):
 *
 *   - `fixed`     — one flat price for the whole job (the uniform-effort desks:
 *                   oracle, dd, treasury, compliance, evalbot).
 *   - `per-unit`  — metered pricing with a billing floor, so a big job costs
 *                   proportionally more than a tiny one (the variable-effort
 *                   desks: sec-audit per file, dep-upgrade per dependency,
 *                   site-auditor per sample, ReviewBot per 100 diff lines).
 *
 * Two number spaces meet here:
 *   - ON-WIRE / base units — the anchored price a listing settles in. USDC is
 *     6-decimal, DEM is 9-decimal OS (§9.5.9), so shown raw they read as the
 *     amateur "1000000000 DEM". `formatFee` renders those the way a person reads
 *     them ("1 DEM"); `baseToDisplay` returns the same as a number.
 *   - DISPLAY units — the human numbers a `FeeSchedule` carries (0.5, 1, 0.1).
 *     `computeFee` and `formatFeeSchedule` operate in this space; a fixed
 *     schedule therefore renders identically to `formatFee` over its base price.
 *
 * NOTE (live conveyance): the anchored DACS-1 Listing schema has NO fee field —
 * the rate lives only in the human `description`. So `formatFeeSchedule` is what
 * a live buyer would read; the in-process mock demos read the structured `fees`
 * directly. Do not put `fees` on the anchored Listing (see wire/butler.ts).
 */
import type { FeeSchedule } from "../../procurement-butler/types.js";

export type { FeeSchedule };

const DECIMALS: Record<string, number> = {
  USDC: 6,
  USDT: 6,
  DAI: 18,
  DEM: 9,
  OS: 0,
};

export function formatFee(amount: string, asset: string): string {
  const dec = DECIMALS[asset.toUpperCase()];
  if (dec === undefined || dec === 0) return `${amount} ${asset}`;
  let n: bigint;
  try {
    n = BigInt(amount);
  } catch {
    return `${amount} ${asset}`;
  }
  const base = 10n ** BigInt(dec);
  const whole = n / base;
  const frac = (n % base).toString().padStart(dec, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac} ${asset}` : `${whole} ${asset}`;
}

/** Base-unit integer string → display-unit number (inverse scale of formatFee). */
export function baseToDisplay(amount: string, asset: string): number {
  const dec = DECIMALS[asset.toUpperCase()];
  if (dec === undefined) return Number(amount);
  return Number(amount) / 10 ** dec;
}

/** Display-unit number → base-unit integer string (for settlement amounts). */
export function displayToBase(display: number, asset: string): string {
  const dec = DECIMALS[asset.toUpperCase()];
  if (dec === undefined) return String(Math.round(display));
  return String(Math.round(display * 10 ** dec));
}

/** Round a display-unit money amount to cents (deterministic, matches the Butler). */
export function roundFee(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * The total bill for a job in DISPLAY units:
 *   - fixed     → the flat price (passthrough).
 *   - per-unit  → max(minTotal, unitPrice * units), so tiny jobs pay the floor
 *                 and big jobs scale linearly. Mirrors the Butler's `askPriceOf`
 *                 so the wire price and the decision price agree.
 */
export function computeFee(fees: FeeSchedule, units: number): number {
  if (fees.kind === "fixed") return roundFee(fees.price);
  return Math.max(fees.minTotal, roundFee(fees.unitPrice * units));
}

/** A fixed `FeeSchedule` in DISPLAY units, derived from a base-unit on-wire price. */
export function fixedFeeFromPrice(price: { amount: string; asset: string }): FeeSchedule {
  return { kind: "fixed", price: baseToDisplay(price.amount, price.asset) };
}

/**
 * Human-readable fee for a listing description:
 *   fixed     → "1 DEM"
 *   per-unit  → "0.5 DEM per file (min 1 DEM)"
 * The fixed branch matches `formatFee` over the same base-unit price.
 */
export function formatFeeSchedule(fees: FeeSchedule, asset: string): string {
  if (fees.kind === "fixed") return `${fees.price} ${asset}`;
  return `${fees.unitPrice} ${asset} per ${fees.unit} (min ${fees.minTotal} ${asset})`;
}
