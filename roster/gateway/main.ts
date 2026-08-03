/**
 * Gateway entrypoint.
 *
 *   npm run gateway:serve
 *
 * Loads config (exits non-zero with a clear message if unsafe to start),
 * builds the shared live ports + attestor, mounts 9 HTTP agents, listens, and
 * handles SIGTERM/SIGINT for graceful shutdown (stop accepting → close → exit).
 */
import { loadConfig, ConfigError } from "./config.js";
import { buildProcurementX402, buildRealPorts, buildX402 } from "./ports.js";
import { buildRegistry } from "./registry.js";
import { createGatewayServer } from "./server.js";
import { warmCompliance } from "../compliance/sources.js";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`[gateway] ${err.message}`);
      process.exit(1);
    }
    throw err;
  }

  const ports = await buildRealPorts();
  const registry = buildRegistry(ports);
  const x402 = await buildX402(registry.map((a) => a.name));
  const procurementX402 = await buildProcurementX402();
  const server = createGatewayServer(config, registry, ports.attestor, ports.outputAnchor, ports.settlement, x402, ports.llm, procurementX402);

  server.listen(config.port, config.bind, () => {
    const mode = config.authEnforced ? "auth ENFORCED" : "DEV MODE — AUTH DISABLED";
    console.error("=".repeat(66));
    console.error(`[gateway] DACS roster gateway v${config.version}`);
    console.error(`[gateway] listening on http://${config.bind}:${config.port}`);
    console.error(`[gateway] ${mode}`);
    if (config.devMode) {
      console.error("[gateway] ⚠️  DEV MODE: no GATEWAY_TOKEN set — POST is OPEN and bind is");
      console.error("[gateway] ⚠️  forced to 127.0.0.1. NEVER run this exposed. Set GATEWAY_TOKEN.");
    }
    console.error(`[gateway] agents (${registry.length}): ${registry.map((a) => a.name).join(", ")}`);
    console.error(`[gateway] open: GET /health, GET /agents, GET /agents/:name`);
    console.error(`[gateway] auth: POST /agents/:name  (Bearer token ${config.authEnforced ? "required" : "not required in dev"})`);
    console.error("=".repeat(66));

    // The PEP source is ~219 MB / ~2M entries and expands to several GB when
    // parsed. Keep that workload opt-in so it cannot cgroup-OOM the live Butler
    // during cryptographic/on-chain work. Dedicated compliance deployments can
    // still warm it explicitly.
    if (process.env.GATEWAY_COMPLIANCE_WARM === "1") {
      console.error("[gateway] warming compliance list cache in background…");
      const warmStart = Date.now();
      void warmCompliance(ports.complianceSources())
        .then((outcomes) => {
          const took = ((Date.now() - warmStart) / 1000).toFixed(1);
          const summary = outcomes.map((o) => `${o.sourceId}=${o.ok ? "ok" : "cold"}`).join(" ");
          console.error(`[gateway] compliance warm complete in ${took}s: ${summary}`);
        })
        .catch((err) => console.error(`[gateway] compliance warm error (non-fatal): ${(err as Error).message}`));
    } else {
      console.error("[gateway] compliance bulk warm disabled (set GATEWAY_COMPLIANCE_WARM=1 on a memory-dedicated deployment)");
    }
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`[gateway] ${signal} received — closing server (no new connections)…`);
    server.close(() => {
      console.error("[gateway] closed cleanly, exiting");
      process.exit(0);
    });
    // Safety net if connections hang.
    setTimeout(() => {
      console.error("[gateway] forced exit after shutdown grace period");
      process.exit(0);
    }, 5_000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  console.error(`[gateway] fatal startup error: ${(err as Error).stack ?? err}`);
  process.exit(1);
});
