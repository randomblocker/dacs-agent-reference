/**
 * Live two-process negotiation over the L2PS messaging server.
 *
 *   npx tsx roster/negotiation-l2ps/live-peers.ts
 *
 * Spawns a seller peer and a buyer peer as SEPARATE processes (distinct crypto
 * identities), each connecting to the live server. They handshake signer ids,
 * then run the signed RFQ end to end — the seller opens, they alternate, and
 * both converge on the same agreement (or both walk). This is the transport
 * proof: the negotiation that runs in-process in the audit desk now runs across
 * two independent agents over a real network channel.
 *
 * Messaging is free (no DEM). The deal frame is shared via env; each side holds
 * only its own private brief.
 */
import { spawn } from "node:child_process";

const SERVER_URL = process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005";
const channelId = `chan-${Date.now()}`;
const sellerClient = `${channelId}-seller`;
const buyerClient = `${channelId}-buyer`;

// A shared deal frame: a mid-size Solidity repo, buyer wants a deep audit with a
// budget that should clear the seller's deep floor after a couple of rounds.
const shared = {
  SERVER_URL,
  CHANNEL_ID: channelId,
  MAX_TURNS: "6",
  DEADLINE: "standard",
};

const sellerEnv = {
  ...process.env,
  ...shared,
  ROLE: "seller",
  MY_CLIENT: sellerClient,
  PEER_CLIENT: buyerClient,
  SCAN_REPO: "acme/payments-core",
  KLOC: "9",
  FILES: "60",
  SOLIDITY: "true",
};
const buyerEnv = {
  ...process.env,
  ...shared,
  ROLE: "buyer",
  MY_CLIENT: buyerClient,
  PEER_CLIENT: sellerClient,
  BUDGET: "30",
  ACCEPTABLE: "deep",
  TIER: "deep",
};

function runPeer(label: string, peerEnv: NodeJS.ProcessEnv): Promise<{ result?: Record<string, unknown>; code: number | null }> {
  return new Promise((resolve) => {
    const child = spawn("npx", ["tsx", "roster/negotiation-l2ps/peer-main.ts"], { env: peerEnv, cwd: process.cwd() });
    let out = "";
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => process.stderr.write(d)); // progress lines
    child.on("close", (code) => {
      const line = out.split("\n").find((l) => l.startsWith("RESULT "));
      let result: Record<string, unknown> | undefined;
      if (line) {
        try {
          result = JSON.parse(line.slice("RESULT ".length));
        } catch {
          /* ignore */
        }
      }
      resolve({ result, code });
    });
  });
}

async function main() {
  console.log(`\n=== Live L2PS negotiation over ${SERVER_URL} ===`);
  console.log(`channel: ${channelId}`);
  console.log(`seller: ${sellerClient} (private scan: 9 KLOC, Solidity ⇒ 2 tools)`);
  console.log(`buyer:  ${buyerClient} (budget 30 DEM, wants deep/standard)\n`);

  const [seller, buyer] = await Promise.all([runPeer("seller", sellerEnv), runPeer("buyer", buyerEnv)]);

  console.log("\n--- results ---");
  console.log("seller:", JSON.stringify(seller.result ?? `(no result, exit ${seller.code})`));
  console.log("buyer: ", JSON.stringify(buyer.result ?? `(no result, exit ${buyer.code})`));

  const sr = seller.result;
  const br = buyer.result;
  if (!sr || !br) {
    console.log("\n❌ one or both peers produced no result");
    process.exit(1);
  }
  const agree = sr.outcome === br.outcome && JSON.stringify(sr.agreed ?? null) === JSON.stringify(br.agreed ?? null);
  if (agree) {
    console.log(`\n✅ both peers ${sr.outcome}${sr.agreed ? `: ${JSON.stringify(sr.agreed)}` : ""} — transport faithful, over the live server`);
    process.exit(0);
  }
  console.log("\n❌ peers disagree on the outcome");
  process.exit(1);
}

main().catch((err) => {
  console.error("live-peers failed:", err);
  process.exit(1);
});
