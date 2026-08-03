/**
 * The distributed negotiation loop — one side of an RFQ run over a `Channel`.
 *
 * This is the two-process form of `audit-negotiator/negotiate.ts#runNegotiation`.
 * Both peers run `runSide` with their own policy + guard + signer; each maintains
 * its own copy of the transcript, rebuilt from the moves it sends and the signed
 * envelopes it receives. The semantics are identical to the in-process engine:
 *
 *   - the seller opens; the sides alternate (seller acts when the transcript has
 *     an even length, buyer when odd);
 *   - a side never emits a move its own guard rejects — the safety net becomes a
 *     signed `reject` on the wire (the peer learns the walk);
 *   - an `accept` binds to the COUNTERPARTY's on-table terms, and each side
 *     re-checks those terms against its OWN guard, so the union of the two checks
 *     is exactly the in-process engine's both-guards check, split across parties;
 *   - `maxTurns` (RFQ-1) and the per-turn receive timeout (RFQ-4) bound the run.
 *
 * The parity test (`session.test.ts`) proves that over an in-process channel this
 * loop reaches the SAME agreement `runNegotiation` does for the same briefs.
 */
import type { AuditTerms, GuardVerdict, NegotiationMove } from "../audit-negotiator/terms.js";
import type { Policy, Turn } from "../audit-negotiator/policies.js";
import type { Channel } from "./channel.js";
import { decodeMove, openEnvelope, sealEnvelope, type ChannelEnvelope, type Signer } from "./wire.js";

export interface SideConfig {
  role: "seller" | "buyer";
  channelId: string;
  policy: Policy;
  /** This side's own settle-predicate (wrap sellerMaySettle / buyerMaySettle). */
  maySettle: (terms: AuditTerms) => GuardVerdict;
  /** The counterparty's stable sender id (for envelope verification). */
  peerSenderId: string;
  signer: Signer;
  channel: Channel;
  maxTurns: number;
  recvTimeoutMs?: number;
  now?: () => number;
  log?: (line: string) => void;
}

export interface NetworkedResult {
  outcome: "agreed" | "walked";
  agreed?: AuditTerms;
  transcript: Turn[];
  /** Every envelope this side sent or received, in sequence order — the signed
   *  record the binding layer hashes (lastMessageHash / transcript hash). */
  envelopes: ChannelEnvelope[];
  reason: string;
  turns: number;
}

/** The terms currently on the table from `side` = its last offer/counter. */
function onTableFrom(transcript: Turn[], side: "seller" | "buyer"): AuditTerms | undefined {
  for (let i = transcript.length - 1; i >= 0; i--) {
    const t = transcript[i]!;
    if (t.side === side && (t.move.kind === "offer" || t.move.kind === "counter")) return t.move.terms;
  }
  return undefined;
}

/** Run one side of the negotiation to termination. */
export async function runSide(cfg: SideConfig): Promise<NetworkedResult> {
  const maxTurns = Math.max(2, cfg.maxTurns);
  const maxRounds = Math.ceil(maxTurns / 2);
  const now = cfg.now ?? (() => Date.now());
  const log = cfg.log ?? (() => {});
  const other: "seller" | "buyer" = cfg.role === "seller" ? "buyer" : "seller";
  // Seller acts on even transcript lengths (0,2,4…), buyer on odd (1,3,5…).
  const myParity = cfg.role === "seller" ? 0 : 1;

  const transcript: Turn[] = [];
  const envelopes: ChannelEnvelope[] = [];
  let myRounds = 0;

  const settleFromAccept = (accepter: "seller" | "buyer"): NetworkedResult => {
    const table = onTableFrom(transcript, accepter === "seller" ? "buyer" : "seller");
    if (!table) return done("walked", undefined, `${accepter} accepted with nothing on the table`);
    const mine = cfg.maySettle(table);
    if (!mine.ok) return done("walked", undefined, `accepted terms fail my guard: ${mine.reason}`);
    return done("agreed", table, `agreed ${table.tier}/${table.deadline} at ${table.price} DEM`);
  };

  function done(outcome: NetworkedResult["outcome"], agreed: AuditTerms | undefined, reason: string): NetworkedResult {
    return { outcome, agreed, transcript, envelopes, reason, turns: transcript.length };
  }

  while (transcript.length < maxTurns) {
    const isMyTurn = transcript.length % 2 === myParity;

    if (isMyTurn) {
      myRounds++;
      let move: NegotiationMove;
      try {
        move = await cfg.policy({ transcript, round: myRounds, maxRounds });
      } catch (err) {
        move = { kind: "reject", rationale: `policy threw: ${(err as Error)?.message ?? err}` };
      }

      // Safety net: never emit a move my own guard rejects. For accept, check the
      // counterparty's on-table terms; for offer/counter, check the move's terms.
      if (move.kind === "accept") {
        const table = onTableFrom(transcript, other);
        const v = table ? cfg.maySettle(table) : { ok: false, reason: "nothing on the table" };
        if (!v.ok) move = { kind: "reject", rationale: `cannot accept: ${v.reason}` };
      } else if (move.kind !== "reject") {
        const v = cfg.maySettle(move.terms);
        if (!v.ok) move = { kind: "reject", rationale: `guard blocked own move: ${v.reason}` };
      }

      const seq = transcript.length + 1;
      const env = await sealEnvelope(cfg.signer, cfg.channelId, seq, move, now());
      await cfg.channel.send(env);
      envelopes.push(env);
      transcript.push({ side: cfg.role, move });
      log(`→ ${cfg.role} ${move.kind}${move.kind === "reject" ? "" : ` ${move.terms.tier}/${move.terms.deadline}@${move.terms.price}`}`);

      if (move.kind === "reject") return done("walked", undefined, `${cfg.role} rejected: ${move.rationale}`);
      if (move.kind === "accept") return settleFromAccept(cfg.role);
    } else {
      let env;
      try {
        env = await cfg.channel.receive(cfg.recvTimeoutMs);
      } catch (err) {
        return done("walked", undefined, `receive failed (RFQ-4 timeout/failure): ${(err as Error)?.message ?? err}`);
      }
      const seq = transcript.length + 1;
      const verdict = await openEnvelope(cfg.signer, env, { channelId: cfg.channelId, sequence: seq, sender: cfg.peerSenderId });
      if (!verdict.ok) return done("walked", undefined, `rejected inbound envelope: ${verdict.reason}`);

      const move = decodeMove(env.body);
      if (!move) return done("walked", undefined, "rejected inbound envelope: invalid negotiation body");
      envelopes.push(env);
      transcript.push({ side: other, move });
      log(`← ${other} ${move.kind}${move.kind === "reject" ? "" : ` ${move.terms.tier}/${move.terms.deadline}@${move.terms.price}`}`);

      if (move.kind === "reject") return done("walked", undefined, `${other} rejected: ${move.rationale}`);
      if (move.kind === "accept") return settleFromAccept(other);
    }
  }

  return done("walked", undefined, `reached maxTurns (${maxTurns}) with no agreement`);
}
