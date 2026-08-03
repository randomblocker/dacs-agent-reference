import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { demosBlockTimestampMs, isKnownNewJobAnchorName } from "./substrate.js";
import { LiveSubstrate } from "./substrate.js";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs";
import { createHash } from "node:crypto";

describe("Demos SR-2 receipt timestamps", () => {
  test("normalises the chain's unix-second timestamp to DACS unix milliseconds", () => {
    assert.equal(demosBlockTimestampMs(1_784_107_266), 1_784_107_266_000);
  });

  test("preserves a node timestamp that is already expressed in milliseconds", () => {
    assert.equal(demosBlockTimestampMs(1_784_107_266_123), 1_784_107_266_123);
  });

  test("rejects missing, negative and unsafe timestamps", () => {
    for (const value of [undefined, "1784107266", -1, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => demosBlockTimestampMs(value), /timestamp/);
    }
  });
});

describe("Demos owner-bound anchor resolution", () => {
  const owner = `did:demos:agent:${"a".repeat(64)}`;

  test("reads a present owner-scoped anchor from the SDK name resolution", async () => {
    const address = `stor-${"b".repeat(40)}`;
    const adapter = {
      resolveAnchorByName: async (_name: string, expectedOwner: string) => {
        assert.equal(expectedOwner, `0x${"a".repeat(64)}`);
        return { status: "present" as const, address };
      },
      readAnchor: async (ref: string) => ref === address ? { revokedAt: 123 } : null,
    };
    const substrate = new LiveSubstrate(adapter as never);
    assert.equal(await substrate.anchorAddressFor(owner, "dacs1:revocation"), address);
    assert.deepEqual(await substrate.readAnchorFor(owner, "dacs1:revocation"), { revokedAt: 123 });
  });

  test("preserves authoritative absence without inventing an address", async () => {
    const adapter = {
      resolveAnchorByName: async () => ({ status: "absent" as const }),
      readAnchor: async () => {
        throw new Error("an absent name must not trigger an address read");
      },
    };
    const substrate = new LiveSubstrate(adapter as never);
    assert.equal(await substrate.readAnchorFor(owner, "dacs1:revocation"), null);
    await assert.rejects(substrate.anchorAddressFor(owner, "dacs1:revocation"), /absent/);
  });

  test("fails closed when owner-bound name resolution is indeterminate", async () => {
    const adapter = {
      resolveAnchorByName: async () => ({ status: "indeterminate" as const, reason: "index unavailable" }),
    };
    const substrate = new LiveSubstrate(adapter as never);
    await assert.rejects(substrate.readAnchorFor(owner, "dacs1:revocation"), /indeterminate/);
  });
});

describe("Demos confirmation-first anchors", () => {
  test("uses the known-new fast path for every per-job DACS slot but not persistent catalog slots", async () => {
    const native = (logical: string) => Buffer.from(logical, "utf8").toString("base64url");
    const jobNames = [
      native("dacs2:composite:job-1:did%3Ademos%3Abuyer"),
      native("dacs3:agreement:job-1"),
      native("dacs3:commit:job-1"),
      native("dacs4:evidence:job-1:pay-dem"),
      native("dacs5:bundle:job-1:buyer"),
      "dacsx:delivery:job-1",
    ];
    for (const name of jobNames) assert.equal(isKnownNewJobAnchorName(name), true, name);
    for (const name of [
      native("dacs1:did%3Ademos%3Aseller:oracle:v1"),
      native("dacs1-revoked:did%3Ademos%3Aseller:oracle:v1"),
      native("dacs3:auto-accept:did%3Ademos%3Aseller:oracle:v1"),
      "unrelated-slot",
    ]) assert.equal(isKnownNewJobAnchorName(name), false, name);

    const modes: Array<string | undefined> = [];
    const adapter = {
      anchor: async (_name: string, _value: object, options?: { nonce?: number; writeMode?: string }) => {
        modes.push(options?.writeMode);
        const nonce = options?.nonce ?? 20;
        return {
          address: "stor-" + String(modes.length).padStart(40, "0"),
          txRef: String(modes.length).padStart(64, "0"),
          broadcastAt: Date.now(),
          nonce,
        };
      },
    };
    const substrate = new LiveSubstrate(adapter as never);
    await substrate.anchorAccepted(jobNames[1]!, { kind: "agreement" });
    await substrate.anchorAccepted(jobNames[5]!, { kind: "delivery" });
    await substrate.anchorAccepted(native("dacs1:did%3Ademos%3Aseller:oracle:v1"), { kind: "listing" });
    assert.deepEqual(modes, ["known-new", "known-new", undefined]);
  });

  test("returns a Vet admission before consensus polling and reserves the next nonce", async () => {
    const nonces: number[] = [];
    let confirmationReads = 0;
    const adapter = {
      anchor: async (_name: string, _value: object, options?: { nonce?: number }) => {
        const nonce = options?.nonce ?? 7;
        nonces.push(nonce);
        return {
          address: "stor-" + String(nonce).padStart(40, "0"),
          txRef: String(nonce).padStart(64, "0"),
          broadcastAt: Date.now(),
          nonce,
        };
      },
      raw: {
        getTxByHash: async () => {
          confirmationReads++;
          return null;
        },
      },
    };
    const substrate = new LiveSubstrate(adapter as never);
    const accepted = await substrate.anchorAccepted("vet", { decision: "pass" });
    assert.equal(accepted.status, "accepted");
    assert.equal(confirmationReads, 0);
    await substrate.anchorAccepted("commitment", { agreementHash: "a".repeat(64) });
    assert.deepEqual(nonces, [7, 8]);
  });

  test("advances past a payment nonce constructed outside the substrate", async () => {
    const nonces: number[] = [];
    const adapter = {
      anchor: async (_name: string, _value: object, options?: { nonce?: number }) => {
        const nonce = options?.nonce ?? 7;
        nonces.push(nonce);
        return {
          address: "stor-" + String(nonce).padStart(40, "0"),
          txRef: String(nonce).padStart(64, "0"),
          broadcastAt: Date.now(),
          nonce,
        };
      },
    };
    const substrate = new LiveSubstrate(adapter as never);
    await substrate.anchorAccepted("commitment", { agreementHash: "a".repeat(64) });
    substrate.noteExternalNonce(8);
    await substrate.anchorAccepted("payment-evidence", { paymentTx: "b".repeat(64) });
    assert.deepEqual(nonces, [7, 9]);
  });

    test("admits ordered same-wallet nonces before awaiting their confirmations together", async () => {
    const events: string[] = [];
    const addresses = {
      agreement: "stor-" + "a".repeat(40),
      commitment: "stor-" + "b".repeat(40),
    };
    const adapter = {
      getAddress: () => "0x" + "f".repeat(64),
      anchor: async (name: "agreement" | "commitment") => {
        events.push(`broadcast:${name}`);
        return {
          address: addresses[name],
          txRef: name === "agreement" ? "1".repeat(64) : "2".repeat(64),
          broadcastAt: Date.now(),
          nonce: name === "agreement" ? 40 : 41,
        };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async (hash: string) => {
          events.push(`confirm:${hash === "1".repeat(64) ? "agreement" : "commitment"}`);
          return {
            status: "confirmed",
            blockNumber: 90,
            content: {
              to: hash === "1".repeat(64) ? addresses.agreement : addresses.commitment,
              data: ["storageProgram", {
                operation: "WRITE_STORAGE",
                data: hash === "1".repeat(64) ? { kind: "agreement" } : { kind: "commitment" },
              }],
            },
          };
        },
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const receipts = await new LiveSubstrate(adapter as never, undefined, {
      unconfirmedReadPolls: 1,
      confirmedReadPolls: 1,
      pollIntervalMs: 0,
    }).anchorBatchWithReceipts([
      { name: "agreement", value: { kind: "agreement" } },
      { name: "commitment", value: { kind: "commitment" } },
    ]);
    assert.deepEqual(events, [
      "broadcast:agreement",
      "broadcast:commitment",
      "confirm:agreement",
      "confirm:commitment",
    ]);
    assert.deepEqual(receipts.map((receipt) => receipt.nonce), [40, 41]);
    assert.deepEqual(receipts.map((receipt) => receipt.address), [addresses.agreement, addresses.commitment]);
  });

  test("independent receipts bind the transaction's exact storage payload", async () => {
    const value = { report: "confirmed", findings: 2 };
    const address = "stor-" + "4".repeat(40);
    const adapter = {
      raw: {
        getTxByHash: async () => ({
          status: "confirmed",
          blockNumber: 71,
          content: { to: address, data: ["storageProgram", { operation: "WRITE_STORAGE", data: value }] },
        }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const receipt = await new LiveSubstrate(adapter as never).resolveAnchorReceipt("d".repeat(64));
    assert.equal(receipt.address, address);
    assert.equal(receipt.blockNumber, 71);
    assert.equal(receipt.contentHash, sha256Hex(canonicalize(value)));
  });

  test("resolves authoritative inclusion from exact transaction content before public indexes hydrate", async () => {
    const value = { report: "included", findings: 1 };
    const address = "stor-" + "9".repeat(40);
    const transactionContent = {
      nonce: 81,
      to: address,
      data: ["storageProgram", { operation: "WRITE_STORAGE", data: value }],
    };
    const txRef = createHash("sha256").update(JSON.stringify(transactionContent), "utf8").digest("hex");
    let historyReads = 0;
    const adapter = {
      raw: {
        getTxByHash: async () => "error",
        call: async () => ({ state: "included", blockNumber: 88 }),
        getTransactionHistory: async () => { historyReads += 1; return []; },
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const receipt = await new LiveSubstrate(adapter as never, undefined, {
      unconfirmedReadPolls: 1,
    }).resolveAnchorReceipt(txRef, undefined, { transactionContent });
    assert.equal(receipt.address, address);
    assert.equal(receipt.blockNumber, 88);
    assert.equal(receipt.contentHash, sha256Hex(canonicalize(value)));
    assert.equal(receipt.transactionContentValueOmitted, true);
    assert.equal(((receipt.transactionContent?.data as unknown[])?.[1] as { data?: unknown })?.data, null);
    assert.equal(historyReads, 0);
  });

  test("rejects an included-status proof whose transaction content hashes to another tx", async () => {
    const transactionContent = {
      nonce: 82,
      to: "stor-" + "a".repeat(40),
      data: ["storageProgram", { operation: "WRITE_STORAGE", data: { ok: true } }],
    };
    const adapter = {
      raw: {
        getTxByHash: async () => "error",
        call: async () => ({ state: "included", blockNumber: 89 }),
      },
    };
    await assert.rejects(
      () => new LiveSubstrate(adapter as never, undefined, { unconfirmedReadPolls: 1 })
        .resolveAnchorReceipt("f".repeat(64), undefined, { transactionContent }),
      /transaction content proof does not match/,
    );
  });

  test("rehydrates a compact receipt proof from the separately transported artifact", async () => {
    const value = { report: "large report is transported once" };
    const address = "stor-" + "b".repeat(40);
    const transactionContent = {
      nonce: 83,
      to: address,
      data: ["storageProgram", { operation: "WRITE_STORAGE", data: value }],
    };
    const compactContent = structuredClone(transactionContent);
    (compactContent.data[1] as { data: unknown }).data = null;
    const txRef = createHash("sha256").update(JSON.stringify(transactionContent), "utf8").digest("hex");
    const adapter = {
      raw: {
        getTxByHash: async () => "error",
        call: async () => ({ state: "included", blockNumber: 90 }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const receipt = await new LiveSubstrate(adapter as never, undefined, { unconfirmedReadPolls: 1 })
      .resolveAnchorReceipt(txRef, undefined, {
        transactionContent: compactContent,
        transactionContentValueOmitted: true,
        anchorValue: value,
      });
    assert.equal(receipt.blockNumber, 90);
    assert.equal(receipt.contentHash, sha256Hex(canonicalize(value)));
  });

  test("returns at confirmed inclusion and reports public visibility later without rebroadcasting", async () => {
    let broadcasts = 0;
    let reads = 0;
    const broadcastAt = Date.now() - 25;
    let publiclyVisible = false;
    let releaseVisibility!: () => void;
    const visible = new Promise<void>((resolve) => { releaseVisibility = resolve; });
    const adapter = {
      anchor: async () => {
        broadcasts += 1;
        return { address: "stor-" + "1".repeat(40), txRef: "a".repeat(64), expectedConfirmationBlock: 40, broadcastAt };
      },
      readAnchor: async () => {
        reads += 1;
        return publiclyVisible ? { ok: true } : null;
      },
      raw: {
        getTxByHash: async () => ({ status: "confirmed", blockNumber: 41, content: { to: "stor-" + "1".repeat(40) } }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const substrate = new LiveSubstrate(adapter as never, undefined, {
      unconfirmedReadPolls: 1,
      confirmedReadPolls: 20,
      pollIntervalMs: 5,
      retryDelayMs: 0,
    }, (record) => {
      if (record.storageStatus === "visible") releaseVisibility();
    });
    const receipt = await substrate.anchorWithReceipt("lagged", { ok: true });
    assert.equal(receipt.address, "stor-" + "1".repeat(40));
    assert.equal(receipt.broadcastAt, broadcastAt);
    assert.ok(receipt.confirmedAt! >= broadcastAt);
    assert.equal(receipt.inclusionLatencyMs, receipt.confirmedAt! - broadcastAt);
    assert.equal(receipt.expectedConfirmationBlock, 40);
    assert.equal(receipt.confirmationBlockDelta, 1);
    assert.equal(broadcasts, 1);
    assert.deepEqual(await substrate.read("stor-" + "1".repeat(40)), { ok: true }, "same-writer reads use the confirmed write-through cache");
    publiclyVisible = true;
    await visible;
    assert.ok(reads >= 1);
    assert.equal(broadcasts, 1);
  });

  test("retries a failed transaction but never rebroadcasts a confirmed visibility lag", async () => {
    let failedBroadcasts = 0;
    const failedThenVisible = {
      anchor: async () => {
        failedBroadcasts += 1;
        return { address: "stor-" + "2".repeat(40), txRef: String(failedBroadcasts).repeat(64) };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async () => ({
          status: failedBroadcasts === 1 ? "failed" : "confirmed",
          blockNumber: 52,
          content: { to: "stor-" + "2".repeat(40) },
        }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266_000 } }),
      },
    };
    const retrying = new LiveSubstrate(failedThenVisible as never, undefined, {
      maxBroadcasts: 2,
      unconfirmedReadPolls: 1,
      confirmedReadPolls: 2,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    assert.equal(await retrying.anchor("retry", { ok: true }), "stor-" + "2".repeat(40));
    assert.equal(failedBroadcasts, 2);

    let confirmedBroadcasts = 0;
    const confirmedButLagged = {
      anchor: async () => {
        confirmedBroadcasts += 1;
        return { address: "stor-" + "3".repeat(40), txRef: "c".repeat(64) };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async () => ({ status: "confirmed", blockNumber: 60, content: { to: "stor-" + "3".repeat(40) } }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const refusingDuplicate = new LiveSubstrate(confirmedButLagged as never, undefined, {
      maxBroadcasts: 3,
      unconfirmedReadPolls: 1,
      confirmedReadPolls: 2,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    assert.equal(await refusingDuplicate.anchor("confirmed", { ok: true }), "stor-" + "3".repeat(40));
    assert.equal(confirmedBroadcasts, 1);

    let pendingBroadcasts = 0;
    const pending = new LiveSubstrate({
      anchor: async () => {
        pendingBroadcasts += 1;
        return { address: "stor-" + "5".repeat(40), txRef: "e".repeat(64) };
      },
      readAnchor: async () => null,
      raw: { getTxByHash: async () => ({ status: "pending" }) },
    } as never, undefined, {
      maxBroadcasts: 3,
      unconfirmedReadPolls: 2,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    await assert.rejects(() => pending.anchor("pending", { ok: true }), /refusing a duplicate broadcast/);
    assert.equal(pendingBroadcasts, 1);
  });

  test("uses confirmed wallet history while the public hash index still returns error", async () => {
    let broadcasts = 0;
    const address = "stor-" + "6".repeat(40);
    const txRef = "f".repeat(64);
    const adapter = {
      getAddress: () => "0x" + "7".repeat(64),
      anchor: async () => {
        broadcasts += 1;
        return { address, txRef };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async () => "error",
        getTransactionHistory: async () => [{
          hash: txRef,
          status: "confirmed",
          blockNumber: 73,
          content: { to: address },
        }],
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const substrate = new LiveSubstrate(adapter as never, undefined, {
      maxBroadcasts: 3,
      unconfirmedReadPolls: 1,
      confirmedReadPolls: 1,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    const receipt = await substrate.anchorWithReceipt("history-visible", { ok: true });
    assert.equal(receipt.txRef, txRef);
    assert.equal(receipt.blockNumber, 73);
    assert.equal(receipt.address, address);
    assert.equal(broadcasts, 1);
  });

  test("resolves a counterparty receipt from that counterparty's wallet history", async () => {
    const ownerHex = "a".repeat(64);
    const ownerDid = `did:demos:agent:${ownerHex}`;
    const txRef = "b".repeat(64);
    const address = "stor-" + "7".repeat(40);
    let queriedAddress = "";
    const adapter = {
      getAddress: () => "0x" + "c".repeat(64),
      raw: {
        getTxByHash: async () => "error",
        call: async () => ({ state: "included", blockNumber: 77 }),
        getTransactionHistory: async (candidate: string) => {
          queriedAddress = candidate;
          return [{
            hash: txRef,
            status: "confirmed",
            blockNumber: 77,
            content: { to: address, data: ["storageProgram", { operation: "WRITE_STORAGE", data: { vetted: true } }] },
          }];
        },
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const receipt = await new LiveSubstrate(adapter as never, undefined, {
      unconfirmedReadPolls: 1,
    }).resolveAnchorReceipt(txRef, ownerDid);
    assert.equal(queriedAddress, `0x${ownerHex}`);
    assert.equal(receipt.address, address);
    assert.equal(receipt.blockNumber, 77);
  });

  test("re-signs with a fresh reference after the authoritative status RPC reports failure", async () => {
    let broadcasts = 0;
    const address = "stor-" + "8".repeat(40);
    const adapter = {
      getAddress: () => "0x" + "9".repeat(64),
      anchor: async () => {
        broadcasts += 1;
        return { address, txRef: broadcasts === 1 ? "1".repeat(64) : "2".repeat(64) };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async () => broadcasts === 1
          ? { status: "pending" }
          : { status: "confirmed", blockNumber: 81, content: { to: address } },
        call: async (_method: string, _message: string) => broadcasts === 1
          ? { state: "failed", blockNumber: 80 }
          : { state: "included", blockNumber: 81 },
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const substrate = new LiveSubstrate(adapter as never, undefined, {
      maxBroadcasts: 2,
      unconfirmedReadPolls: 1,
      confirmedReadPolls: 1,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    const receipt = await substrate.anchorWithReceipt("expired-reference", { ok: true });
    assert.equal(receipt.txRef, "2".repeat(64));
    assert.equal(receipt.blockNumber, 81);
    assert.equal(broadcasts, 2);
  });

  test("rebroadcasts a dropped transaction with the same reserved nonce", async () => {
    let broadcasts = 0;
    const nonces: Array<number | undefined> = [];
    const address = "stor-" + "d".repeat(40);
    const firstTx = "3".repeat(64);
    const secondTx = "4".repeat(64);
    const adapter = {
      getAddress: () => "0x" + "a".repeat(64),
      anchor: async (_name: string, _value: object, options?: { nonce?: number }) => {
        broadcasts += 1;
        nonces.push(options?.nonce);
        return {
          address,
          txRef: broadcasts === 1 ? firstTx : secondTx,
          nonce: 73,
          expectedConfirmationBlock: broadcasts === 1 ? 100 : 104,
        };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async (hash: string) => hash === firstTx
          ? "error"
          : { status: "confirmed", blockNumber: 104, content: { to: address } },
        getTransactionHistory: async () => [],
        getLastBlockNumber: async () => 103,
        call: async () => ({ state: "unknown" }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const substrate = new LiveSubstrate(adapter as never, undefined, {
      maxBroadcasts: 2,
      unconfirmedReadPolls: 3,
      confirmedReadPolls: 1,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    const receipt = await substrate.anchorWithReceipt("dropped-reference", { ok: true });
    assert.equal(receipt.txRef, secondTx);
    assert.equal(receipt.blockNumber, 104);
    assert.equal(broadcasts, 2);
    assert.deepEqual(nonces, [undefined, 73]);
  });

  test("rebroadcasts a dropped accepted receipt with the same reserved nonce", async () => {
    let broadcasts = 0;
    const nonces: Array<number | undefined> = [];
    const address = "stor-" + "e".repeat(40);
    const firstTx = "5".repeat(64);
    const secondTx = "6".repeat(64);
    const adapter = {
      getAddress: () => "0x" + "b".repeat(64),
      anchor: async (_name: string, _value: object, options?: { nonce?: number }) => {
        broadcasts += 1;
        nonces.push(options?.nonce);
        return {
          address,
          txRef: broadcasts === 1 ? firstTx : secondTx,
          nonce: 91,
          expectedConfirmationBlock: broadcasts === 1 ? 120 : 124,
          broadcastAt: 1_784_107_266_000 + broadcasts,
        };
      },
      readAnchor: async () => null,
      raw: {
        getTxByHash: async (hash: string) => hash === firstTx
          ? "error"
          : {
              status: "confirmed",
              blockNumber: 124,
              content: { to: address, data: ["storageProgram", { operation: "WRITE_STORAGE", data: { vetted: true } }] },
            },
        getTransactionHistory: async () => [],
        getLastBlockNumber: async () => 123,
        call: async () => ({ state: "unknown" }),
        getBlockByNumber: async () => ({ content: { timestamp: 1_784_107_266 } }),
      },
    };
    const substrate = new LiveSubstrate(adapter as never, undefined, {
      maxBroadcasts: 2,
      unconfirmedReadPolls: 3,
      confirmedReadPolls: 1,
      pollIntervalMs: 0,
      retryDelayMs: 0,
    });
    const accepted = await substrate.anchorAccepted("accepted-vet", { vetted: true });
    const receipt = await substrate.confirmAcceptedAnchor(accepted);
    assert.equal(receipt.txRef, secondTx);
    assert.equal(receipt.blockNumber, 124);
    assert.equal(receipt.nonce, 91);
    assert.equal(broadcasts, 2);
    assert.deepEqual(nonces, [undefined, 91]);
  });
});
