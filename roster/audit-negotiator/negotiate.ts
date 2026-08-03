/**
 * The RFQ negotiation harness — runs a seller policy against a buyer policy over
 * a bounded number of turns and returns the agreed terms (or a walk) plus the
 * full transcript.
 *
 * This is the substrate-independent core of DACS-3's RFQ pattern (§8.4.2). It is
 * transport-agnostic: here the two policies run in-process, but the exact same
 * `Turn[]` transcript is what `l2ps.channel.ChannelSession` would carry as signed
 * `ChannelMessage`s over the wire (that binding is the next phase). What lives
 * here is the part the spec leaves entirely to the implementation — the turn
 * content and strategy — wrapped in the parts it does NOT: the maxTurns cap
 * (RFQ-1), and the guard invariants applied to every move so no policy, LLM or
 * otherwise, can settle outside its own bounds.
 *
 * Acceptance is bound to the counterparty's ON-TABLE terms, never to a price a
 * party restates unilaterally — so the agreed deal is exactly the last proposal
 * both guards accept. That is what later serialises into a signed
 * AgreementDocument.
 */
import {
  buyerMaySettle,
  sellerMaySettle,
  type AuditTerms,
  type BuyerGuard,
  type NegotiationMove,
  type SellerGuard,
} from "./terms.js";
import type { Policy, Turn } from "./policies.js";

export interface NegotiationConfig {
  /** RFQ-1 hard cap on total turns across both sides (spec default 6, min 2). */
  maxTurns: number;
  sellerGuard: SellerGuard;
  buyerGuard: BuyerGuard;
}

export interface NegotiationResult {
  outcome: "agreed" | "walked";
  /** Present iff agreed — the terms both guards accepted. */
  agreed?: AuditTerms;
  transcript: Turn[];
  /** Human-readable close reason (agreement summary or why it walked). */
  reason: string;
  turns: number;
}

/** The terms currently "on the table" from a side = its last offer/counter. */
function onTableFrom(transcript: Turn[], side: "seller" | "buyer"): AuditTerms | undefined {
  for (let i = transcript.length - 1; i >= 0; i--) {
    const t = transcript[i]!;
    if (t.side === side && (t.move.kind === "offer" || t.move.kind === "counter")) return t.move.terms;
  }
  return undefined;
}

/** Validate a move a side is about to emit against that side's own guard. */
function guardEmittedMove(move: NegotiationMove, side: "seller" | "buyer", cfg: NegotiationConfig): { ok: boolean; reason?: string } {
  if (move.kind === "reject") return { ok: true };
  const terms = move.terms;
  return side === "seller" ? sellerMaySettle(terms, cfg.sellerGuard) : buyerMaySettle(terms, cfg.buyerGuard);
}

/**
 * Run the negotiation. Seller opens, then the sides alternate (seller, buyer,
 * seller, …). Terminates on the first `accept` that both guards clear, on a
 * `reject`, on a policy emitting a move its own guard rejects (treated as a
 * walk — the safety net), or when `maxTurns` is reached (timeout ⇒ walk).
 */
export async function runNegotiation(seller: Policy, buyer: Policy, cfg: NegotiationConfig): Promise<NegotiationResult> {
  const maxTurns = Math.max(2, cfg.maxTurns);
  const transcript: Turn[] = [];
  let sellerRounds = 0;
  let buyerRounds = 0;

  for (let turn = 0; turn < maxTurns; turn++) {
    const side: "seller" | "buyer" = turn % 2 === 0 ? "seller" : "buyer";
    const policy = side === "seller" ? seller : buyer;
    const round = side === "seller" ? ++sellerRounds : ++buyerRounds;
    const maxRounds = Math.ceil(maxTurns / 2);

    let move: NegotiationMove;
    try {
      move = await policy({ transcript, round, maxRounds });
    } catch (err) {
      return finish("walked", undefined, `${side} policy threw: ${(err as Error)?.message ?? err}`, transcript, turn);
    }

    // Safety net: a side may never emit a move that breaches its own guard.
    const emitOk = guardEmittedMove(move, side, cfg);
    if (!emitOk.ok) {
      const clamped: Turn = { side, move: { kind: "reject", rationale: `guard blocked own move: ${emitOk.reason}` } };
      transcript.push(clamped);
      return finish("walked", undefined, `${side} produced an out-of-guard move (${emitOk.reason}); walked`, transcript, turn + 1);
    }

    transcript.push({ side, move });

    if (move.kind === "reject") {
      return finish("walked", undefined, `${side} rejected: ${move.rationale}`, transcript, turn + 1);
    }

    if (move.kind === "accept") {
      // Bind to the OTHER side's on-table terms — never the accepter's restatement.
      const other: "seller" | "buyer" = side === "seller" ? "buyer" : "seller";
      const table = onTableFrom(transcript, other);
      if (!table) {
        return finish("walked", undefined, `${side} accepted with nothing on the table`, transcript, turn + 1);
      }
      const sOk = sellerMaySettle(table, cfg.sellerGuard);
      const bOk = buyerMaySettle(table, cfg.buyerGuard);
      if (sOk.ok && bOk.ok) {
        return finish("agreed", table, `agreed ${table.tier}/${table.deadline} at ${table.price} DEM`, transcript, turn + 1);
      }
      return finish(
        "walked",
        undefined,
        `accepted terms fail a guard (seller: ${sOk.reason ?? "ok"}; buyer: ${bOk.reason ?? "ok"})`,
        transcript,
        turn + 1,
      );
    }
    // offer/counter: continue the loop.
  }

  return finish("walked", undefined, `reached maxTurns (${maxTurns}) with no agreement`, transcript, maxTurns);
}

function finish(
  outcome: NegotiationResult["outcome"],
  agreed: AuditTerms | undefined,
  reason: string,
  transcript: Turn[],
  turns: number,
): NegotiationResult {
  return { outcome, agreed, transcript, reason, turns };
}

/** Pretty-print a transcript for logs/demos. */
export function formatTranscript(result: NegotiationResult): string {
  const lines: string[] = [];
  for (const t of result.transcript) {
    const m = t.move;
    const tag = `${t.side.padEnd(6)} ${m.kind.padEnd(7)}`;
    const terms = m.kind === "reject" ? "" : `${m.terms.tier}/${m.terms.deadline} @ ${m.terms.price} DEM  `;
    lines.push(`  ${tag} ${terms}— ${m.rationale}`);
  }
  lines.push(`  => ${result.outcome.toUpperCase()}: ${result.reason} (${result.turns} turns)`);
  return lines.join("\n");
}
