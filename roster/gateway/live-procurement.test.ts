import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { broadcastNativePayment, LiveProcurementError, LiveProcurementJobs, oracleProtocolRequest, parseProcurementInput, type ProcurementJob } from "./live-procurement.js";

class ControllableProcurementJobs extends LiveProcurementJobs {
  readonly executionOrder: string[] = [];
  private readonly controls = new Map<string, { resolve: () => void; reject: (error: Error) => void }>();

  override readiness(): { executable: boolean; reasons: string[] } {
    return { executable: true, reasons: [] };
  }

  protected override async run(job: ProcurementJob, _input: unknown): Promise<void> {
    this.executionOrder.push(job.id);
    await new Promise<void>((resolve, reject) => this.controls.set(job.id, { resolve, reject }));
    job.status = "complete";
    job.phase = "complete";
    job.updatedAt = new Date().toISOString();
  }

  complete(id: string): void {
    const control = this.controls.get(id);
    assert.ok(control, `job ${id} is not active`);
    control.resolve();
  }

  fail(id: string, message = "controlled failure"): void {
    const control = this.controls.get(id);
    assert.ok(control, `job ${id} is not active`);
    control.reject(new Error(message));
  }
}

class RecoveryObservingJobs extends LiveProcurementJobs {
  readonly recoveryRequests: string[] = [];

  override readiness(): { executable: boolean; reasons: string[] } {
    return { executable: true, reasons: [] };
  }

  override recover(id: string): ProcurementJob {
    this.recoveryRequests.push(id);
    return this.get(id);
  }
}

async function waitUntil(predicate: () => boolean, message: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  assert.fail(message);
}

function queueInput(goal: string): Record<string, unknown> {
  return { profileId: "security-audit-rfq", goal, budgetDem: 5, files: [{ path: "server.js", content: "eval(input)" }] };
}

test("bounded procurement queue is FIFO, observable, capacity-safe, and idempotent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-queue-"));
  const previousQueueLimit = process.env.DACS_PROCUREMENT_QUEUE_LIMIT;
  const previousHourlyLimit = process.env.DACS_PROCUREMENT_HOURLY_LIMIT;
  process.env.DACS_PROCUREMENT_QUEUE_LIMIT = "2";
  process.env.DACS_PROCUREMENT_HOURLY_LIMIT = "20";
  try {
    const jobs = new ControllableProcurementJobs(dir);
    const first = jobs.startRequest(queueInput("first"), "queue-first").job;
    const second = jobs.startRequest(queueInput("second"), "queue-second").job;
    const replay = jobs.startRequest(queueInput("second"), "queue-second");
    const third = jobs.startRequest(queueInput("third"), "queue-third").job;

    assert.equal(replay.replayed, true);
    assert.equal(replay.job.id, second.id);
    assert.equal(jobs.get(first.id).queue?.status, "active");
    assert.equal(jobs.get(second.id).queue?.status, "waiting");
    assert.equal(jobs.get(second.id).queue?.position, 1);
    assert.equal(jobs.get(third.id).queue?.position, 2);
    assert.deepEqual(jobs.executionOrder, [first.id]);
    assert.throws(
      () => jobs.startRequest(queueInput("fourth"), "queue-fourth"),
      (error: unknown) => error instanceof LiveProcurementError && error.status === 503 && /queue is full/.test(error.message),
    );

    jobs.complete(first.id);
    await waitUntil(() => jobs.executionOrder.length === 2, "second queued job did not start");
    assert.deepEqual(jobs.executionOrder, [first.id, second.id]);
    assert.equal(jobs.get(second.id).queue?.status, "active");
    assert.equal(jobs.get(third.id).queue?.position, 1);

    jobs.complete(second.id);
    await waitUntil(() => jobs.executionOrder.length === 3, "third queued job did not start");
    assert.deepEqual(jobs.executionOrder, [first.id, second.id, third.id]);
    jobs.complete(third.id);
    await waitUntil(() => jobs.get(third.id).queue?.status === "finished", "final queued job did not finish");
    assert.equal(jobs.get(first.id).status, "complete");
    assert.equal(jobs.get(second.id).status, "complete");
    assert.equal(jobs.get(third.id).status, "complete");
  } finally {
    if (previousQueueLimit === undefined) delete process.env.DACS_PROCUREMENT_QUEUE_LIMIT;
    else process.env.DACS_PROCUREMENT_QUEUE_LIMIT = previousQueueLimit;
    if (previousHourlyLimit === undefined) delete process.env.DACS_PROCUREMENT_HOURLY_LIMIT;
    else process.env.DACS_PROCUREMENT_HOURLY_LIMIT = previousHourlyLimit;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a failed procurement releases the lane to the next queued job", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-queue-failure-"));
  const previousQueueLimit = process.env.DACS_PROCUREMENT_QUEUE_LIMIT;
  const previousHourlyLimit = process.env.DACS_PROCUREMENT_HOURLY_LIMIT;
  process.env.DACS_PROCUREMENT_QUEUE_LIMIT = "1";
  process.env.DACS_PROCUREMENT_HOURLY_LIMIT = "20";
  try {
    const jobs = new ControllableProcurementJobs(dir);
    const first = jobs.startRequest(queueInput("fails"), "queue-fails").job;
    const second = jobs.startRequest(queueInput("continues"), "queue-continues").job;
    jobs.fail(first.id, "first job failed safely");
    await waitUntil(() => jobs.executionOrder.length === 2, "failure did not release the procurement lane");
    assert.equal(jobs.get(first.id).status, "failed");
    assert.equal(jobs.get(first.id).failedBeforePayment, true);
    assert.equal(jobs.get(second.id).queue?.status, "active");
    jobs.complete(second.id);
    await waitUntil(() => jobs.get(second.id).queue?.status === "finished", "second job did not finish");
    assert.equal(jobs.get(second.id).status, "complete");
  } finally {
    if (previousQueueLimit === undefined) delete process.env.DACS_PROCUREMENT_QUEUE_LIMIT;
    else process.env.DACS_PROCUREMENT_QUEUE_LIMIT = previousQueueLimit;
    if (previousHourlyLimit === undefined) delete process.env.DACS_PROCUREMENT_HOURLY_LIMIT;
    else process.env.DACS_PROCUREMENT_HOURLY_LIMIT = previousHourlyLimit;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("public procurement receipts survive restart and interrupted runs fail visibly", () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-jobs-"));
  const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const now = new Date().toISOString();
  const running: ProcurementJob = {
    id, status: "running", phase: "settling", createdAt: now, updatedAt: now,
    events: [{ phase: "queued", label: "queued", at: now }],
  };
  try {
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(running), { mode: 0o600 });
    const jobs = new LiveProcurementJobs(dir);
    const recovered = jobs.get(id);
    assert.equal(recovered.status, "failed");
    assert.equal(recovered.phase, "failed");
    assert.match(recovered.error ?? "", /gateway restarted/);
    assert.match(recovered.events.at(-1)?.label ?? "", /gateway restart/);
    const stored = JSON.parse(readFileSync(join(dir, `${id}.json`), "utf8")) as ProcurementJob;
    assert.equal(stored.status, "failed");
    assert.equal(statSync(join(dir, `${id}.json`)).mode & 0o777, 0o600);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verified DACS-5 finalisation resumes after restart only when the canary flag is enabled", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-finalisation-restart-"));
  const id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const now = new Date().toISOString();
  const previous = process.env.DACS_DURABLE_ASYNC_FINALISATION;
  const running: ProcurementJob = {
    id,
    profileId: "security-audit-rfq",
    status: "running",
    phase: "verifying",
    createdAt: now,
    updatedAt: now,
    events: [
      { phase: "discovering", label: "Verified the Auditor listing", at: now, anchorRef: `stor-${"a".repeat(64)}` },
      { phase: "settling", label: "Payment broadcast on Demos", at: now, txRef: "b".repeat(64) },
      { phase: "delivering", label: "Verified report ready; both parties are anchoring their final DACS-5 copies", at: now },
    ],
    preview: { status: "report-verified-finalising-dacs5" },
    finalisation: { status: "running", startedAt: now, updatedAt: now, attempts: 1 },
    sessionRecord: {
      recordVersion: "1",
      jobId: id,
      state: "settle-pending",
      listingRef: {} as never,
      parties: [],
      pipeline: [],
      phaseResults: [],
      startedAt: Date.now(),
      lastUpdatedAt: Date.now(),
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
    },
  };
  try {
    process.env.DACS_DURABLE_ASYNC_FINALISATION = "1";
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(running), { mode: 0o600 });
    const jobs = new RecoveryObservingJobs(dir);
    await waitUntil(() => jobs.recoveryRequests.length === 1, "durable finalisation was not resumed");
    assert.deepEqual(jobs.recoveryRequests, [id]);
    const resumed = jobs.get(id);
    assert.equal(resumed.status, "failed",
      "the normal recovery method owns the transition back to running; the observing test double only records it");
    assert.equal(resumed.failedBeforePayment, false);
    assert.equal(resumed.sessionRecord?.state, "aborted-by-self");
    assert.equal(resumed.finalisation?.status, "running");
    assert.equal(resumed.preview && (resumed.preview as { status?: string }).status, "report-verified-finalising-dacs5");
  } finally {
    if (previous === undefined) delete process.env.DACS_DURABLE_ASYNC_FINALISATION;
    else process.env.DACS_DURABLE_ASYNC_FINALISATION = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("interrupted DACS-5 work stays failed when durable finalisation is disabled", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-finalisation-disabled-"));
  const id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const now = new Date().toISOString();
  const previous = process.env.DACS_DURABLE_ASYNC_FINALISATION;
  try {
    delete process.env.DACS_DURABLE_ASYNC_FINALISATION;
    writeFileSync(join(dir, `${id}.json`), JSON.stringify({
      id,
      status: "running",
      phase: "verifying",
      createdAt: now,
      updatedAt: now,
      events: [{ phase: "settling", label: "Payment broadcast on Demos", at: now, txRef: "c".repeat(64) }],
      preview: { status: "delivery-verified-finalising-dacs5" },
      finalisation: { status: "running", startedAt: now, updatedAt: now, attempts: 1 },
    } satisfies ProcurementJob), { mode: 0o600 });
    const jobs = new RecoveryObservingJobs(dir);
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.deepEqual(jobs.recoveryRequests, []);
    assert.equal(jobs.get(id).finalisation?.status, "failed");
  } finally {
    if (previous === undefined) delete process.env.DACS_DURABLE_ASYNC_FINALISATION;
    else process.env.DACS_DURABLE_ASYNC_FINALISATION = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a persisted transient finalisation retry resumes after another gateway restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-finalisation-retry-restart-"));
  const id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const now = new Date().toISOString();
  const previous = process.env.DACS_DURABLE_ASYNC_FINALISATION;
  try {
    process.env.DACS_DURABLE_ASYNC_FINALISATION = "1";
    writeFileSync(join(dir, `${id}.json`), JSON.stringify({
      id,
      profileId: "oracle-auto-accept",
      status: "failed",
      phase: "failed",
      error: "Recovery failed: Target peer dacs-oracle-fixed not found",
      createdAt: now,
      updatedAt: now,
      events: [{ phase: "settling", label: "Payment broadcast on Demos", at: now, txRef: "d".repeat(64) }],
      preview: { status: "delivery-verified-finalising-dacs5" },
      finalisation: {
        status: "running",
        startedAt: now,
        updatedAt: now,
        attempts: 2,
        lastError: "Target peer dacs-oracle-fixed not found",
      },
      sessionRecord: {
        recordVersion: "1",
        jobId: id,
        state: "aborted-by-self",
        listingRef: {},
        parties: [],
        pipeline: [],
        phaseResults: [],
        startedAt: Date.now(),
        lastUpdatedAt: Date.now(),
        endedAt: Date.now(),
        recipeRegistryVersion: 1,
        railRegistryVersion: 1,
      },
    } satisfies ProcurementJob), { mode: 0o600 });
    const jobs = new RecoveryObservingJobs(dir);
    await waitUntil(() => jobs.recoveryRequests.length === 1, "persisted transient finalisation retry was not resumed");
    assert.deepEqual(jobs.recoveryRequests, [id]);
  } finally {
    if (previous === undefined) delete process.env.DACS_DURABLE_ASYNC_FINALISATION;
    else process.env.DACS_DURABLE_ASYNC_FINALISATION = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("failedBeforePayment is crash-safe: any persisted settling event fails closed", () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-fbp-"));
  const now = new Date().toISOString();
  const base = (id: string, events: ProcurementJob["events"], recovery?: ProcurementJob["recovery"]): ProcurementJob => ({
    id, status: "running", phase: "settling", createdAt: now, updatedAt: now, events, ...(recovery ? { recovery } : {}),
  });
  // Crashed INSIDE the broadcast window: "Paying …" persisted, no txRef event yet.
  const paidWindow = "aaaaaaaa-0000-4aaa-8aaa-aaaaaaaaaaa1";
  // Crashed before any settling activity: provably unpaid.
  const preSettle = "aaaaaaaa-0000-4aaa-8aaa-aaaaaaaaaaa2";
  // Crashed during paid-job recovery: paid by definition.
  const recovering = "aaaaaaaa-0000-4aaa-8aaa-aaaaaaaaaaa3";
  try {
    writeFileSync(join(dir, `${paidWindow}.json`), JSON.stringify(base(paidWindow, [
      { phase: "queued", label: "queued", at: now },
      { phase: "settling", label: "Paying 2 DEM to the negotiated Auditor", at: now },
    ])), { mode: 0o600 });
    writeFileSync(join(dir, `${preSettle}.json`), JSON.stringify(base(preSettle, [
      { phase: "queued", label: "queued", at: now },
      { phase: "connecting", label: "Connecting the Butler buyer wallet", at: now },
    ])), { mode: 0o600 });
    writeFileSync(join(dir, `${recovering}.json`), JSON.stringify(base(recovering, [
      { phase: "queued", label: "queued", at: now },
      { phase: "settling", label: "Payment broadcast on Demos", at: now, txRef: "tx-1" },
      { phase: "recovering", label: "Recovering paid job", at: now },
    ], { status: "running", startedAt: now, updatedAt: now, originalError: "boom" })), { mode: 0o600 });

    const jobs = new LiveProcurementJobs(dir);
    assert.equal(jobs.get(paidWindow).status, "failed");
    assert.equal(jobs.get(paidWindow).failedBeforePayment, false,
      "a persisted 'Paying …' event means broadcast MAY have happened — must fail closed");
    assert.equal(jobs.get(preSettle).failedBeforePayment, true,
      "a job that never reached settling is provably unpaid");
    assert.equal(jobs.get(recovering).failedBeforePayment, false,
      "an interrupted paid-job recovery is paid by definition");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unconfigured live procurement profiles fail before a job or payment can exist", () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-profile-"));
  try {
    const jobs = new LiveProcurementJobs(dir);
    assert.throws(() => jobs.startRequest({
      profileId: "oracle-auto-accept",
      product: "crypto-price",
      params: { id: "bitcoin" },
    }, "oracle-profile-test"), /profile is unavailable.*Oracle DACS-1 listing binding/);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("procurement input is a closed profile union and the legacy RFQ default stays stable", () => {
  const rfq = parseProcurementInput({
    goal: "audit this source",
    budgetDem: 5,
    files: [{ path: "server.js", content: "eval(input)" }],
  });
  assert.equal(rfq.profileId, "security-audit-rfq");
  assert.throws(
    () => parseProcurementInput({ profileId: "made-up", goal: "x", budgetDem: 5 }),
    (error: unknown) => error instanceof LiveProcurementError && error.status === 400,
  );
});

test("all three production profiles accept an explicit x402 request contract", () => {
  const oracle = parseProcurementInput({
    profileId: "oracle-auto-accept",
    product: "crypto-price",
    params: { id: "bitcoin" },
    paymentRail: "pay-x402",
  });
  const dd = parseProcurementInput({
    profileId: "dd-live-fixed",
    kind: "npm-package",
    subject: "express",
    paymentRail: "pay-x402",
  });
  const security = parseProcurementInput({
    profileId: "security-audit-rfq",
    goal: "audit this source",
    budgetUsdc: 0.05,
    files: [{ path: "server.js", content: "eval(input)" }],
    paymentRail: "pay-x402",
  });
  assert.ok("paymentRail" in oracle && oracle.paymentRail === "pay-x402");
  assert.ok("paymentRail" in dd && dd.paymentRail === "pay-x402");
  assert.ok("paymentRail" in security && security.paymentRail === "pay-x402");
  assert.ok("budgetDem" in security && security.budgetDem === 0.05);
  assert.throws(() => parseProcurementInput({
    profileId: "security-audit-rfq",
    goal: "audit this source",
    budgetDem: 5,
    files: [{ path: "server.js", content: "eval(input)" }],
    paymentRail: "pay-x402",
  }), /budgetUsdc/);
});

test("Oracle demo input becomes the flat request shape consumed by the seller catalog", () => {
  const input = parseProcurementInput({
    profileId: "oracle-auto-accept",
    product: "crypto-price",
    params: { id: "bitcoin" },
  });
  assert.equal(input.profileId, "oracle-auto-accept");
  assert.deepEqual(oracleProtocolRequest(input), { id: "bitcoin", product: "crypto-price" });
});

test("native payment retries a proven drop with the same nonce", async () => {
  let transfers = 0;
  const requestedNonces: Array<number | undefined> = [];
  const hashes = ["1".repeat(64), "2".repeat(64)];
  const wallet = {
    async transfer(_to: string, _amount: bigint, options?: { nonce?: number }) {
      requestedNonces.push(options?.nonce);
      return { hash: hashes[transfers++]!, content: { nonce: options?.nonce ?? 11 } };
    },
    async confirm(tx: unknown) { return tx; },
    async broadcast(tx: { hash: string }) {
      return { result: 200, response: { hash: tx.hash }, extra: { confirmationBlock: 20 } };
    },
    async getAddressInfo() { return { nonce: 10 }; },
    async getLastBlockNumber() { return 23; },
    async call(_method: string, _message: string, data: { hash: string }) {
      return data.hash === hashes[0]
        ? { state: "unknown" }
        : { state: "included", blockNumber: 24 };
    },
  };
  const broadcasts: string[] = [];
  const receipt = await broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1n, {
    rpcTimeoutMs: 20,
    confirmTimeoutMs: 20,
    attemptTimeoutMs: 20,
    pollIntervalMs: 0,
    onBroadcast: (candidate) => broadcasts.push(candidate.txHash),
  });
  assert.equal(receipt.txHash, hashes[1]);
  assert.equal(receipt.nonce, 11);
  assert.equal(receipt.blockNumber, 24);
  assert.deepEqual(requestedNonces, [undefined, 11]);
  assert.deepEqual(broadcasts, hashes);
});

test("native payment never duplicates an indeterminate pending broadcast", async () => {
  let transfers = 0;
  const hash = "3".repeat(64);
  const wallet = {
    async transfer() { transfers += 1; return { hash, content: { nonce: 11 } }; },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    async getAddressInfo() { return { nonce: 10 }; },
    async getLastBlockNumber() { return 30; },
    async call() { return { state: "pending" }; },
  };
  await assert.rejects(() => broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1n, {
    attempts: 3,
    rpcTimeoutMs: 20,
    confirmTimeoutMs: 20,
    attemptTimeoutMs: 5,
    pollIntervalMs: 1,
  }), /remained pending; refusing a duplicate payment/);
  assert.equal(transfers, 1);
});

test("native payment uses the confirmed commitment successor nonce instead of a stale address projection", async () => {
  const requested: Array<number | undefined> = [];
  const hash = "4".repeat(64);
  const wallet = {
    async transfer(_to: string, _amount: bigint, options?: { nonce?: number }) {
      requested.push(options?.nonce);
      return { hash, content: { nonce: options?.nonce } };
    },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    // Deliberately stale: the ordered anchors already consumed nonces 386/387.
    async getAddressInfo() { return { nonce: 386 }; },
    async getLastBlockNumber() { return 20; },
    async call() { return { state: "included", blockNumber: 20 }; },
  };
  const receipt = await broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1n, {
    nonce: 388,
    rpcTimeoutMs: 20,
    confirmTimeoutMs: 20,
    attemptTimeoutMs: 20,
    pollIntervalMs: 0,
  });
  assert.equal(receipt.nonce, 388);
  assert.deepEqual(requested, [388]);
});

test("native payment direct-confirmation fast path verifies the exact signed transfer", async () => {
  const hash = "5".repeat(64);
  const content = { type: "native", from: "0xbuyer", to: "0xseller", amount: "1000000000", nonce: 11 };
  let directReads = 0;
  const wallet = {
    async transfer() { return { hash, content }; },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    async getAddressInfo() { return { nonce: 10 }; },
    async getLastBlockNumber() { return 20; },
    async call() { return { state: "pending" }; },
    async getTxByHash(requested: string) {
      directReads += 1;
      assert.equal(requested, hash);
      return { hash, status: "confirmed", blockNumber: 21, content };
    },
  };
  const receipt = await broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1_000_000_000n, {
    directConfirmation: true,
    rpcTimeoutMs: 20,
    confirmTimeoutMs: 20,
    attemptTimeoutMs: 20,
    pollIntervalMs: 0,
  });
  assert.equal(receipt.blockNumber, 21);
  assert.equal(receipt.attempt, 1);
  assert.equal(directReads, 1);
});

test("native payment direct-confirmation fails closed on content substitution", async () => {
  const hash = "6".repeat(64);
  const content = { type: "native", from: "0xbuyer", to: "0xseller", amount: "1000000000", nonce: 11 };
  const wallet = {
    async transfer() { return { hash, content }; },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    async getAddressInfo() { return { nonce: 10 }; },
    async getLastBlockNumber() { return 21; },
    async call() { return { state: "pending" }; },
    async getTxByHash() {
      return { hash, status: "confirmed", blockNumber: 21, content: { ...content, to: "0xattacker" } };
    },
  };
  await assert.rejects(
    () => broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1_000_000_000n, {
      directConfirmation: true,
      rpcTimeoutMs: 20,
      confirmTimeoutMs: 20,
      attemptTimeoutMs: 20,
      pollIntervalMs: 0,
    }),
    /did not match the intended payment/,
  );
});

test("native payment accepts node-enriched confirmed content when all payment fields still match", async () => {
  const hash = "9".repeat(64);
  const signedContent = {
    type: "native",
    from: "0xbuyer",
    to: "0xseller",
    amount: "1000000000",
    nonce: 11,
    timestamp: "123",
  };
  const confirmedContent = {
    ...signedContent,
    amount: 1_000_000_000,
    nonce: "11",
    from_ed25519_address: "0xbuyer",
    transaction_fee: { network_fee: 1_000_000_000 },
    data: ["native", { nativeOperation: "send", args: ["0xseller", "1000000000"] }],
    gcr_edits: [{ type: "balance", txhash: hash }],
  };
  const wallet = {
    async transfer() { return { hash, content: signedContent }; },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    async getAddressInfo() { return { nonce: 10 }; },
    async getLastBlockNumber() { return 21; },
    async call() { return { state: "pending" }; },
    async getTxByHash() { return { hash, status: "confirmed", blockNumber: 21, content: confirmedContent }; },
  };
  const receipt = await broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1_000_000_000n, {
    directConfirmation: true,
    rpcTimeoutMs: 20,
    confirmTimeoutMs: 20,
    attemptTimeoutMs: 20,
    pollIntervalMs: 0,
  });
  assert.equal(receipt.blockNumber, 21);
  assert.deepEqual(receipt.transactionContent, signedContent,
    "the seller proof retains the original hash-bound content, not the node-enriched projection");
});

test("native payment never retries an absent hash after the reserved nonce advanced", async () => {
  let transfers = 0;
  const hash = "7".repeat(64);
  const content = { type: "send", from: "0xbuyer", to: "0xseller", amount: "1", nonce: 11 };
  const wallet = {
    async transfer() { transfers += 1; return { hash, content }; },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    async getAddressInfo() { return { nonce: 12 }; },
    async getLastBlockNumber() { return 23; },
    async call() { return { state: "unknown" }; },
    async getTxByHash() { return null; },
  };
  await assert.rejects(
    () => broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1n, {
      directConfirmation: true,
      attempts: 3,
      rpcTimeoutMs: 20,
      confirmTimeoutMs: 20,
      attemptTimeoutMs: 20,
      pollIntervalMs: 0,
    }),
    /buyer nonce advanced; refusing a duplicate payment/,
  );
  assert.equal(transfers, 1);
});

test("native payment direct lookup remains disabled by default", async () => {
  const hash = "8".repeat(64);
  let directReads = 0;
  const wallet = {
    async transfer() { return { hash, content: { nonce: 11 } }; },
    async confirm(tx: unknown) { return tx; },
    async broadcast() { return { result: 200, response: { hash }, extra: { confirmationBlock: 20 } }; },
    async getAddressInfo() { return { nonce: 10 }; },
    async getLastBlockNumber() { return 20; },
    async call() { return { state: "included", blockNumber: 20 }; },
    async getTxByHash() { directReads += 1; return null; },
  };
  await broadcastNativePayment(wallet, "0xbuyer", "0xseller", 1n, {
    rpcTimeoutMs: 20,
    confirmTimeoutMs: 20,
    attemptTimeoutMs: 20,
    pollIntervalMs: 0,
  });
  assert.equal(directReads, 0);
});

test("production readiness fails closed on missing bindings and unsafe wallet permissions", () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-ready-"));
  const key = join(dir, "buyer.key");
  const previousKey = process.env.DACS_PROCUREMENT_BUYER_KEY_FILE;
  const previousListing = process.env.DACS_AUDITOR_LISTING_REF;
  const previousDid = process.env.DACS_AUDITOR_DID;
  const previousResearcher = process.env.DACS_AUDITOR_RESEARCHER_GITHUB;
  try {
    writeFileSync(key, "test mnemonic only\n", { mode: 0o644 });
    process.env.DACS_PROCUREMENT_BUYER_KEY_FILE = key;
    delete process.env.DACS_AUDITOR_LISTING_REF;
    delete process.env.DACS_AUDITOR_RESEARCHER_GITHUB;
    const jobs = new LiveProcurementJobs(join(dir, "jobs"));
    const unsafe = jobs.readiness("security-audit-rfq");
    assert.equal(unsafe.executable, false);
    assert.ok(unsafe.reasons.some((reason) => reason.includes("permissions")));
    assert.ok(unsafe.reasons.some((reason) => reason.includes("listing binding")));
    assert.ok(unsafe.reasons.some((reason) => reason.includes("researcher GitHub")));

    chmodSync(key, 0o600);
    process.env.DACS_AUDITOR_LISTING_REF = `stor-${"a".repeat(64)}`;
    process.env.DACS_AUDITOR_DID = `did:demos:agent:${"b".repeat(64)}`;
    process.env.DACS_AUDITOR_RESEARCHER_GITHUB = "dacs-security-researcher";
    assert.deepEqual(jobs.readiness("security-audit-rfq"), { executable: true, reasons: [] });
  } finally {
    if (previousKey === undefined) delete process.env.DACS_PROCUREMENT_BUYER_KEY_FILE;
    else process.env.DACS_PROCUREMENT_BUYER_KEY_FILE = previousKey;
    if (previousListing === undefined) delete process.env.DACS_AUDITOR_LISTING_REF;
    else process.env.DACS_AUDITOR_LISTING_REF = previousListing;
    if (previousDid === undefined) delete process.env.DACS_AUDITOR_DID;
    else process.env.DACS_AUDITOR_DID = previousDid;
    if (previousResearcher === undefined) delete process.env.DACS_AUDITOR_RESEARCHER_GITHUB;
    else process.env.DACS_AUDITOR_RESEARCHER_GITHUB = previousResearcher;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("restart retains every persisted job and idempotency record regardless of count or filename order", () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-many-"));
  const now = new Date().toISOString();
  try {
    // 150 completed jobs whose UUIDs sort AFTER the critical one, so any
    // lexicographic .slice(-N) cap would evict the critical record.
    for (let i = 0; i < 150; i++) {
      const id = `ffffffff-${String(i).padStart(4, "0")}-4fff-8fff-ffffffffffff`;
      const createdAt = new Date(Date.parse(now) - (150 - i) * 60_000).toISOString();
      writeFileSync(join(dir, `${id}.json`), JSON.stringify({
        id, status: "complete", phase: "complete", createdAt, updatedAt: createdAt,
        events: [{ phase: "queued", label: "queued", at: createdAt }], result: { ok: true, seq: i },
      }), { mode: 0o600 });
    }
    // The critical record: an unresolved (running → failed-on-restart) job in
    // the broadcast window, holding an idempotency key. Sorts FIRST, so a
    // lexicographic .slice(-N) cap would have evicted exactly this record.
    const critical = "00000000-0000-4000-8000-000000000001";
    const rawKey = "3f1c2b34-5566-4777-8888-999900aabbcc";
    const rawInput = { goal: "benchmark goal", budgetDem: 5, files: [{ path: "a.js", content: "x" }] };
    // Mirror the gateway's own hashing (sha256 of the normalized key; sha256
    // of the fixed-order input encoding with auditorListingRef defaulted).
    const storedKeyHash = createHash("sha256").update(rawKey).digest("hex");
    const storedInputHash = createHash("sha256").update(JSON.stringify({
      goal: rawInput.goal, budgetDem: rawInput.budgetDem,
      files: rawInput.files.map((file) => ({ path: file.path, content: file.content })),
      auditorListingRef: null,
    })).digest("hex");
    writeFileSync(join(dir, `${critical}.json`), JSON.stringify({
      id: critical, status: "running", phase: "settling", createdAt: now, updatedAt: now,
      events: [
        { phase: "queued", label: "queued", at: now },
        { phase: "settling", label: "Paying 2 DEM to the negotiated Auditor", at: now },
      ],
      idempotency: { keyHash: storedKeyHash, inputHash: storedInputHash },
    }), { mode: 0o600 });

    const jobs = new LiveProcurementJobs(dir);
    const recovered = jobs.get(critical);
    assert.equal(recovered.status, "failed");
    assert.equal(recovered.failedBeforePayment, false);
    // A lost-response retry with the same key must replay THIS job, never
    // create a second paid one.
    const replay = jobs.startRequest(rawInput, rawKey);
    assert.equal(replay.replayed, true);
    assert.equal(replay.job.id, critical);
    // The OLDEST complete job is beyond the keep-full window, so its
    // in-memory record is a slim index entry — but reads must hydrate the
    // full body (events + result) from disk.
    const oldest = "ffffffff-0000-4fff-8fff-ffffffffffff";
    const hydrated = jobs.get(oldest);
    assert.equal(hydrated.status, "complete");
    assert.equal(hydrated.events.length, 1, "archived complete jobs hydrate their events from disk");
    assert.deepEqual(hydrated.result, { ok: true, seq: 0 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an exact idempotency replay automatically resumes a failed job with a persisted payment receipt", () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-procurement-auto-recovery-"));
  const now = new Date().toISOString();
  const paidId = "11111111-1111-4111-8111-111111111111";
  const unpaidId = "22222222-2222-4222-8222-222222222222";
  const paidKey = "paid-recovery-key";
  const unpaidKey = "unpaid-replay-key";
  const paidInput = queueInput("recover the paid audit");
  const unpaidInput = queueInput("replay the unpaid audit");
  const inputHash = (input: Record<string, unknown>): string => {
    const files = input.files as Array<{ path: string; content: string }>;
    return createHash("sha256").update(JSON.stringify({
      goal: input.goal,
      budgetDem: input.budgetDem,
      files: files.map((file) => ({ path: file.path, content: file.content })),
      auditorListingRef: null,
    })).digest("hex");
  };
  const session = (id: string) => ({
    recordVersion: "1",
    jobId: id,
    state: "aborted-by-self",
    listingRef: {},
    parties: [],
    pipeline: [],
    phaseResults: [],
    startedAt: Date.now(),
    lastUpdatedAt: Date.now(),
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
  });
  try {
    writeFileSync(join(dir, `${paidId}.json`), JSON.stringify({
      id: paidId, status: "failed", phase: "failed", createdAt: now, updatedAt: now,
      events: [
        { phase: "queued", label: "queued", at: now },
        { phase: "settling", label: "Payment broadcast on Demos", at: now, txRef: "a".repeat(64) },
      ],
      failedBeforePayment: false,
      sessionRecord: session(paidId),
      idempotency: {
        keyHash: createHash("sha256").update(paidKey).digest("hex"),
        inputHash: inputHash(paidInput),
      },
    }), { mode: 0o600 });
    writeFileSync(join(dir, `${unpaidId}.json`), JSON.stringify({
      id: unpaidId, status: "failed", phase: "failed", createdAt: now, updatedAt: now,
      events: [{ phase: "queued", label: "queued", at: now }],
      failedBeforePayment: true,
      sessionRecord: session(unpaidId),
      idempotency: {
        keyHash: createHash("sha256").update(unpaidKey).digest("hex"),
        inputHash: inputHash(unpaidInput),
      },
    }), { mode: 0o600 });

    const jobs = new RecoveryObservingJobs(dir);
    const paidReplay = jobs.startRequest(paidInput, paidKey);
    const unpaidReplay = jobs.startRequest(unpaidInput, unpaidKey);

    assert.equal(paidReplay.replayed, true);
    assert.equal(paidReplay.job.id, paidId);
    assert.deepEqual(jobs.recoveryRequests, [paidId],
      "only an exact replay with a concrete persisted payment tx enters recovery");
    assert.equal(unpaidReplay.replayed, true);
    assert.equal(unpaidReplay.job.id, unpaidId);
    assert.equal(unpaidReplay.job.status, "failed",
      "a provably unpaid failure remains a receipt replay and never spends automatically");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
