/**
 * Live LiveDahr demo/probe — attests a real public JSON URL through the Demos
 * node's DAHR web2 proxy, verifies the attestation offline, then verifies the
 * on-chain anchor, printing exactly what each step DOES and does NOT prove.
 *
 *   npm run roster:oracle-live
 *   PROBE_URL=https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd npm run roster:oracle-live
 *
 * Requires DEMOS_MNEMONIC because each fetch broadcasts a fee-paid web2Request
 * anchor. The source tree never carries a funded wallet mnemonic.
 */
import { DemosAdapter } from "@kynesyslabs/dacs/substrate";

import { verifyAttestation } from "./attested-fetch.js";
import { LiveDahr, RealDahrProxy, verifyLiveAnchorOnChain, type DemosLike, type TxReader } from "./live-dahr.js";

const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const MNEMONIC = (() => {
  const value = process.env.DEMOS_MNEMONIC?.trim();
  if (!value) throw new Error("DEMOS_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();
const URL = process.env.PROBE_URL ?? "https://api.frankfurter.dev/v1/latest?base=USD&symbols=EUR";

async function main() {
  console.log("LiveDahr demo — real DAHR attested fetch\n");
  const adapter = new DemosAdapter({ rpc: RPC, secret: MNEMONIC });
  console.log(`connecting ${RPC} …`);
  await adapter.connect();
  const demos = adapter.raw as unknown as DemosLike;
  console.log(`wallet: ${adapter.getAddress()}\n`);

  const live = new LiveDahr(new RealDahrProxy(demos));
  console.log(`attestFetch ${URL} …`);
  const t0 = Date.now();
  const res = await live.attestFetch(URL);
  console.log(`  (${Date.now() - t0}ms)`);
  console.log(`  status        ${res.status}`);
  console.log(`  body          ${res.body.slice(0, 80)}${res.body.length > 80 ? "…" : ""}`);
  console.log(`  bodyHash      sha256:${res.bodyHash.slice(0, 24)}…`);
  console.log(`  scheme        ${res.attestation.scheme}`);
  console.log(`  digest        ${res.attestation.digest.slice(0, 24)}…  (= node responseHash)`);
  console.log(`  anchorTxRef   ${res.attestation.anchorTxRef || "(not broadcast)"}`);
  console.log(`  committedBy   ${res.attestation.publicKey}\n`);

  console.log("1) OFFLINE verifyAttestation (body ↔ responseHash):");
  const offline = verifyAttestation(res);
  console.log(`   -> ${offline.valid ? "VALID" : "INVALID: " + offline.reason}`);
  console.log("   proves: the body you hold hashes to the committed responseHash.\n");

  console.log("2) ON-CHAIN verifyLiveAnchorOnChain (the anchor tx):");
  const reader: TxReader = { getTxByHash: (h) => (demos as unknown as TxReader).getTxByHash(h) };
  const anchor = await verifyLiveAnchorOnChain(res, reader);
  if (anchor.valid) {
    console.log(`   -> VALID  (block ${anchor.blockNumber}, committedBy ${anchor.committedBy})`);
    console.log(`   PROVES:        ${anchor.proves}`);
    console.log(`   DOES NOT PROVE: ${anchor.doesNotProve}`);
  } else {
    console.log(`   -> INVALID: ${anchor.reason}`);
  }

  console.log("\nBottom line: real DAHR is a self-observed commitment (distinct-party");
  console.log("fetch + persistent on-chain anchor), NOT a consensus/TLSNotary proof.");
  await (adapter.raw as { disconnect?: () => Promise<void> }).disconnect?.().catch(() => {});
  process.exit(0);
}
main().catch((e) => {
  console.error("LIVE DEMO FAILED:", e?.stack ?? e?.message ?? e);
  process.exit(1);
});
