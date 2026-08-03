/**
 * One negotiation peer, as a standalone process. The parent (`live-peers.ts`)
 * spawns two of these — a seller and a buyer — against the live L2PS messaging
 * server; they handshake, then run the signed RFQ to termination. Each prints a
 * single `RESULT <json>` line the parent parses.
 *
 * Scenario params arrive via env so both sides share the deal frame while each
 * holds only its own private info (the seller the scan/floors, the buyer the
 * budget). Run indirectly via `live-peers.ts`; not meant to be run alone.
 */
import { initIdentity } from "./demosdk.js";
import { LivePeer } from "./live-peer.js";
import { runSide } from "./session.js";
import {
  DEFAULT_ECONOMICS,
  buyerMaySettle,
  sellerMaySettle,
  toolsForScan,
  type AuditTier,
  type BuyerGuard,
  type Deadline,
  type ScanFacts,
} from "../audit-negotiator/terms.js";
import { deterministicBuyer, deterministicSeller, sellerGuardFor } from "../audit-negotiator/policies.js";

const TIERS: AuditTier[] = ["quick", "deep"];
const DEADLINES: Deadline[] = ["standard", "rush"];

function env(name: string, dflt = ""): string {
  return process.env[name] ?? dflt;
}

async function main() {
  const role = env("ROLE") as "seller" | "buyer";
  const serverUrl = env("SERVER_URL", "ws://demosnode.discus.sh:3005");
  const channelId = env("CHANNEL_ID");
  const myClientId = env("MY_CLIENT");
  const peerClientId = env("PEER_CLIENT");
  const maxTurns = Number(env("MAX_TURNS", "6"));
  const deadline = env("DEADLINE", "standard") as Deadline;

  const identity = await initIdentity();
  const peer = new LivePeer(serverUrl, myClientId, identity.mlkemPublicKey);
  await peer.connect();
  const peerSignerId = await peer.handshake(peerClientId, identity.signerId);
  const channel = peer.channel(peerClientId, channelId);

  // Build this side's policy + guard from its private brief.
  let side;
  if (role === "seller") {
    const hasSolidity = env("SOLIDITY", "false") === "true";
    const scan: ScanFacts = {
      repo: env("SCAN_REPO", "target/repo"),
      kloc: Number(env("KLOC", "10")),
      fileCount: Number(env("FILES", "40")),
      hasSolidity,
      numTools: toolsForScan(hasSolidity),
    };
    const guard = sellerGuardFor(scan, TIERS, DEADLINES, DEFAULT_ECONOMICS);
    side = {
      role,
      channelId,
      policy: deterministicSeller({ scan, guard, econ: DEFAULT_ECONOMICS }),
      maySettle: (t: import("../audit-negotiator/terms.js").AuditTerms) => sellerMaySettle(t, guard),
    };
  } else {
    const budget = Number(env("BUDGET", "20"));
    const acceptableTiers = env("ACCEPTABLE", "deep").split(",").filter(Boolean) as AuditTier[];
    const preferredTier = (env("TIER", "deep") as AuditTier);
    const guard: BuyerGuard = { offeredTiers: TIERS, offeredDeadlines: DEADLINES, budget, acceptableTiers };
    side = {
      role,
      channelId,
      policy: deterministicBuyer({ guard, preferredTier, preferredDeadline: deadline }),
      maySettle: (t: import("../audit-negotiator/terms.js").AuditTerms) => buyerMaySettle(t, guard),
    };
  }

  const result = await runSide({
    ...side,
    peerSenderId: peerSignerId,
    signer: identity.signer,
    channel,
    maxTurns,
    recvTimeoutMs: 30_000,
    log: (l) => console.error(`[${role}] ${l}`), // progress to stderr; RESULT to stdout
  });

  console.log(`RESULT ${JSON.stringify({ role, outcome: result.outcome, agreed: result.agreed, turns: result.turns, reason: result.reason, signerId: identity.signerId })}`);
  peer.disconnect();
  // Give the socket a beat to flush, then exit.
  setTimeout(() => process.exit(0), 300);
}

main().catch((err) => {
  console.error("peer error:", err?.message ?? err);
  process.exit(1);
});
