import type { FieldSpec } from "./types.js";

export type ProcurementMode =
  | "fixed-price-auto-accept"
  | "fixed-price-live-cosign"
  | "rfq"
  | "sealed-envelope";

export type ProcurementImplementationStatus = "live" | "provisioning";

export interface ProcurementRailInput {
  rail: "pay-dem" | "pay-x402";
  fields: readonly FieldSpec[];
  sampleInput: Record<string, unknown>;
}

export interface ProcurementProfile {
  id: string;
  title: string;
  agentName: string;
  serviceId: string;
  mode: ProcurementMode;
  negotiationPhase: "negotiate-fixed-price" | "negotiate-rfq" | "negotiate-sealed-envelope";
  summary: string;
  fields: readonly FieldSpec[];
  sampleInput: Record<string, unknown>;
  /** Rail-specific request contracts exposed to live clients. */
  railInputs: readonly ProcurementRailInput[];
  timing: {
    healthyMinSec: number;
    healthyMaxSec: number;
    hardTimeoutSec: number;
    /** Protocol-enforced time before chain/agent latency is added. */
    protocolFloorSec: number;
  };
  /**
   * The public demo runs every phase server-side after one start request.
   * It does not pause for interactive commit/payment confirmation.
   */
  executionControl: {
    model: "server-orchestrated";
    interactiveConfirmation: false;
  };
  /**
   * The public lab is the buyer: it creates the DACS identity and signs and
   * settles with operator-held demo wallets. External buyer signers are not
   * accepted by this endpoint.
   */
  buyerControl: {
    model: "gateway-custodied-demo";
    acceptsExternalDacsIdentity: false;
    acceptsExternalPaymentSigner: false;
  };
  /** Production settlement rails independently preflighted by the gateway. */
  paymentRails: readonly ("pay-dem" | "pay-x402")[];
  implementationStatus: ProcurementImplementationStatus;
  unavailableReason?: string;
}

/**
 * Public catalogue for the four production procurement experiences. A profile
 * remains `provisioning` until its independently keyed seller process, signed
 * listing, and end-to-end paid conformance test are installed. The UI must not
 * turn provisioning profiles into executable controls.
 */
export const PROCUREMENT_PROFILES: readonly ProcurementProfile[] = [
  {
    id: "oracle-auto-accept",
    title: "Buy attested data now",
    agentName: "Oracle Desk",
    serviceId: "oracle-data",
    mode: "fixed-price-auto-accept",
    negotiationPhase: "negotiate-fixed-price",
    summary: "Buy a posted-price, source-attested public data point through a seller-side auto-accept commitment.",
    fields: [
      { name: "product", type: "string", required: true, enum: ["crypto-price", "fx-rate", "chain-height"], desc: "attested data product" },
      { name: "params", type: "object", required: false, desc: "product parameters" },
    ],
    sampleInput: { product: "crypto-price", params: { id: "bitcoin" } },
    railInputs: [
      {
        rail: "pay-dem",
        fields: [
          { name: "product", type: "string", required: true, enum: ["crypto-price", "fx-rate", "chain-height"], desc: "attested data product" },
          { name: "params", type: "object", required: false, desc: "product parameters" },
        ],
        sampleInput: { product: "crypto-price", params: { id: "bitcoin" }, paymentRail: "pay-dem" },
      },
      {
        rail: "pay-x402",
        fields: [
          { name: "product", type: "string", required: true, enum: ["crypto-price", "fx-rate", "chain-height"], desc: "attested data product" },
          { name: "params", type: "object", required: false, desc: "product parameters" },
          { name: "paymentRail", type: "string", required: true, enum: ["pay-x402"], desc: "settle in Base Sepolia USDC through x402" },
        ],
        sampleInput: { product: "crypto-price", params: { id: "bitcoin" }, paymentRail: "pay-x402" },
      },
    ],
    timing: { healthyMinSec: 60, healthyMaxSec: 90, hardTimeoutSec: 180, protocolFloorSec: 0 },
    executionControl: { model: "server-orchestrated", interactiveConfirmation: false },
    buyerControl: {
      model: "gateway-custodied-demo",
      acceptsExternalDacsIdentity: false,
      acceptsExternalPaymentSigner: false,
    },
    paymentRails: ["pay-dem", "pay-x402"],
    implementationStatus: "live",
  },
  {
    id: "dd-live-fixed",
    title: "Accept a posted research offer",
    agentName: "Due-Diligence Researcher",
    serviceId: "dd-research",
    mode: "fixed-price-live-cosign",
    negotiationPhase: "negotiate-fixed-price",
    summary: "Accept the listed report price and obtain a live per-session seller co-signature before payment.",
    fields: [
      { name: "kind", type: "string", required: true, enum: ["npm-package", "crypto-token"], desc: "research subject type" },
      { name: "subject", type: "string", required: true, desc: "npm package name or CoinGecko coin id" },
    ],
    sampleInput: { kind: "npm-package", subject: "express" },
    railInputs: [
      {
        rail: "pay-dem",
        fields: [
          { name: "kind", type: "string", required: true, enum: ["npm-package", "crypto-token"], desc: "research subject type" },
          { name: "subject", type: "string", required: true, desc: "npm package name or CoinGecko coin id" },
        ],
        sampleInput: { kind: "npm-package", subject: "express", paymentRail: "pay-dem" },
      },
      {
        rail: "pay-x402",
        fields: [
          { name: "kind", type: "string", required: true, enum: ["npm-package", "crypto-token"], desc: "research subject type" },
          { name: "subject", type: "string", required: true, desc: "npm package name or CoinGecko coin id" },
          { name: "paymentRail", type: "string", required: true, enum: ["pay-x402"], desc: "settle in Base Sepolia USDC through x402" },
        ],
        sampleInput: { kind: "npm-package", subject: "express", paymentRail: "pay-x402" },
      },
    ],
    timing: { healthyMinSec: 90, healthyMaxSec: 180, hardTimeoutSec: 300, protocolFloorSec: 0 },
    executionControl: { model: "server-orchestrated", interactiveConfirmation: false },
    buyerControl: {
      model: "gateway-custodied-demo",
      acceptsExternalDacsIdentity: false,
      acceptsExternalPaymentSigner: false,
    },
    paymentRails: ["pay-dem", "pay-x402"],
    implementationStatus: "live",
  },
  {
    id: "security-audit-rfq",
    title: "Negotiate a security audit",
    agentName: "Security Auditor",
    serviceId: "audit-negotiator",
    mode: "rfq",
    negotiationPhase: "negotiate-rfq",
    summary: "Negotiate scope and price over a signed private channel, then buy and verify the resulting audit.",
    fields: [
      { name: "goal", type: "string", required: true, desc: "security outcome required" },
      { name: "budgetDem", type: "number", required: true, min: 1, max: 10, desc: "maximum DEM spend" },
      { name: "files", type: "array", required: true, desc: "1-3 posted source files" },
    ],
    sampleInput: {
      goal: "Find exploitable security issues in this posted source",
      budgetDem: 5,
      files: [{ path: "server.js", content: "const userInput = process.argv[2];\neval(userInput);\n" }],
    },
    railInputs: [
      {
        rail: "pay-dem",
        fields: [
          { name: "goal", type: "string", required: true, desc: "security outcome required" },
          { name: "budgetDem", type: "number", required: true, min: 1, max: 10, desc: "maximum DEM spend" },
          { name: "files", type: "array", required: true, desc: "1-3 posted source files" },
        ],
        sampleInput: {
          goal: "Find exploitable security issues in this posted source",
          budgetDem: 5,
          files: [{ path: "server.js", content: "const userInput = process.argv[2];\neval(userInput);\n" }],
          paymentRail: "pay-dem",
        },
      },
      {
        rail: "pay-x402",
        fields: [
          { name: "goal", type: "string", required: true, desc: "security outcome required" },
          { name: "budgetUsdc", type: "number", required: true, min: 0.000001, max: 10, desc: "maximum Base Sepolia USDC spend" },
          { name: "files", type: "array", required: true, desc: "1-3 posted source files" },
          { name: "paymentRail", type: "string", required: true, enum: ["pay-x402"], desc: "settle in Base Sepolia USDC through x402" },
        ],
        sampleInput: {
          goal: "Find exploitable security issues in this posted source",
          budgetUsdc: 0.10,
          files: [{ path: "server.js", content: "const userInput = process.argv[2];\neval(userInput);\n" }],
          paymentRail: "pay-x402",
        },
      },
    ],
    timing: { healthyMinSec: 90, healthyMaxSec: 180, hardTimeoutSec: 300, protocolFloorSec: 0 },
    executionControl: { model: "server-orchestrated", interactiveConfirmation: false },
    buyerControl: {
      model: "gateway-custodied-demo",
      acceptsExternalDacsIdentity: false,
      acceptsExternalPaymentSigner: false,
    },
    paymentRails: ["pay-dem", "pay-x402"],
    implementationStatus: "live",
  },
  {
    id: "publisher-ad-rfq",
    title: "Negotiate domain advertising",
    agentName: "Publisher Agent",
    serviceId: "publisher-ad-rfq",
    mode: "rfq",
    negotiationPhase: "negotiate-rfq",
    summary: "Negotiate placement, duration and price for a policy-reviewed advert on a Demos-verified publisher domain.",
    fields: [
      { name: "creative", type: "object", required: true, desc: "headline, body, CTA, and canonical HTTPS destination" },
      { name: "preferredPlacement", type: "string", required: true, enum: ["homepage-banner", "sidebar-card"], desc: "requested inventory slot" },
      { name: "preferredDurationDays", type: "integer", required: true, min: 1, max: 30, desc: "preferred campaign duration" },
      { name: "minimumDurationDays", type: "integer", required: true, min: 1, max: 30, desc: "shortest acceptable counter-offer" },
      { name: "budgetDem", type: "string", required: true, desc: "maximum DEM spend as decimal text" },
    ],
    sampleInput: {
      creative: { headline: "Build verifiable agent commerce", body: "See DACS agents negotiate, settle and verify real work.", cta: "Try it", destinationUrl: "https://dacs.directory/try" },
      preferredPlacement: "homepage-banner",
      preferredDurationDays: 7,
      minimumDurationDays: 3,
      budgetDem: "20",
    },
    railInputs: [
      {
        rail: "pay-dem",
        fields: [
          { name: "creative", type: "object", required: true, desc: "headline, body, CTA, and canonical HTTPS destination" },
          { name: "preferredPlacement", type: "string", required: true, enum: ["homepage-banner", "sidebar-card"], desc: "requested inventory slot" },
          { name: "preferredDurationDays", type: "integer", required: true, min: 1, max: 30, desc: "preferred campaign duration" },
          { name: "minimumDurationDays", type: "integer", required: true, min: 1, max: 30, desc: "shortest acceptable counter-offer" },
          { name: "budgetDem", type: "string", required: true, desc: "maximum DEM spend as decimal text" },
        ],
        sampleInput: {
          creative: { headline: "Build verifiable agent commerce", body: "See DACS agents negotiate, settle and verify real work.", cta: "Try it", destinationUrl: "https://dacs.directory/try" },
          preferredPlacement: "homepage-banner", preferredDurationDays: 7, minimumDurationDays: 3, budgetDem: "20", paymentRail: "pay-dem",
        },
      },
      {
        rail: "pay-x402",
        fields: [
          { name: "creative", type: "object", required: true, desc: "headline, body, CTA, and canonical HTTPS destination" },
          { name: "preferredPlacement", type: "string", required: true, enum: ["homepage-banner", "sidebar-card"], desc: "requested inventory slot" },
          { name: "preferredDurationDays", type: "integer", required: true, min: 1, max: 30, desc: "preferred campaign duration" },
          { name: "minimumDurationDays", type: "integer", required: true, min: 1, max: 30, desc: "shortest acceptable counter-offer" },
          { name: "budgetUsdc", type: "string", required: true, desc: "maximum Base Sepolia USDC spend as decimal text" },
          { name: "paymentRail", type: "string", required: true, enum: ["pay-x402"], desc: "settle through x402" },
        ],
        sampleInput: {
          creative: { headline: "Build verifiable agent commerce", body: "See DACS agents negotiate, settle and verify real work.", cta: "Try it", destinationUrl: "https://dacs.directory/try" },
          preferredPlacement: "homepage-banner", preferredDurationDays: 7, minimumDurationDays: 3, budgetUsdc: "0.20", paymentRail: "pay-x402",
        },
      },
    ],
    timing: { healthyMinSec: 30, healthyMaxSec: 90, hardTimeoutSec: 180, protocolFloorSec: 0 },
    executionControl: { model: "server-orchestrated", interactiveConfirmation: false },
    buyerControl: {
      model: "gateway-custodied-demo",
      acceptsExternalDacsIdentity: false,
      acceptsExternalPaymentSigner: false,
    },
    paymentRails: ["pay-dem", "pay-x402"],
    implementationStatus: "provisioning",
    unavailableReason: "requires a configured publisher domain and Demos GCR domain identity, a generic placement/duration RFQ transport, production moderation, atomic inventory reservation, activation API, and paid conformance run",
  },
  {
    id: "sponsored-post-live",
    title: "Buy a sponsored post",
    agentName: "Sponsored Post Agent",
    serviceId: "sponsored-post",
    mode: "fixed-price-live-cosign",
    negotiationPhase: "negotiate-fixed-price",
    summary: "Buy one policy-approved post from the dedicated DACS demo X account, with a live seller co-signature and public delivery evidence.",
    fields: [
      { name: "text", type: "string", required: true, desc: "exact 1-240 character post; no links, mentions, control characters, or hidden rewriting" },
    ],
    sampleInput: { text: "DACS agents can negotiate, pay, deliver, and verify work on open rails. #DACS" },
    railInputs: [
      {
        rail: "pay-dem",
        fields: [
          { name: "text", type: "string", required: true, desc: "exact 1-240 character post; no links, mentions, control characters, or hidden rewriting" },
        ],
        sampleInput: { text: "DACS agents can negotiate, pay, deliver, and verify work on open rails. #DACS", paymentRail: "pay-dem" },
      },
      {
        rail: "pay-x402",
        fields: [
          { name: "text", type: "string", required: true, desc: "exact 1-240 character post; no links, mentions, control characters, or hidden rewriting" },
          { name: "paymentRail", type: "string", required: true, enum: ["pay-x402"], desc: "settle in Base Sepolia USDC through x402" },
        ],
        sampleInput: { text: "DACS agents can negotiate, pay, deliver, and verify work on open rails. #DACS", paymentRail: "pay-x402" },
      },
    ],
    timing: { healthyMinSec: 20, healthyMaxSec: 60, hardTimeoutSec: 120, protocolFloorSec: 0 },
    executionControl: { model: "server-orchestrated", interactiveConfirmation: false },
    buyerControl: {
      model: "gateway-custodied-demo",
      acceptsExternalDacsIdentity: false,
      acceptsExternalPaymentSigner: false,
    },
    paymentRails: ["pay-dem", "pay-x402"],
    implementationStatus: "provisioning",
    unavailableReason: "requires a dedicated X account, OAuth user access token, fail-closed moderation service, public DACS-to-X account proof post, and paid end-to-end conformance run",
  },
  {
    id: "dd-sealed-tender",
    title: "Run a competitive research tender",
    agentName: "Competitive DD Tender",
    serviceId: "dd-research-tender",
    mode: "sealed-envelope",
    negotiationPhase: "negotiate-sealed-envelope",
    summary: "Collect independently anchored sealed bids from vetted researchers and award the lowest conforming bid.",
    fields: [
      { name: "kind", type: "string", required: true, enum: ["npm-package", "crypto-token"], desc: "research subject type" },
      { name: "subject", type: "string", required: true, desc: "npm package name or CoinGecko coin id" },
      { name: "maxPriceDem", type: "number", required: true, min: 1, max: 10, desc: "inclusive reserve price ceiling" },
    ],
    sampleInput: { kind: "npm-package", subject: "express", maxPriceDem: 5 },
    railInputs: [{
      rail: "pay-dem",
      fields: [
        { name: "kind", type: "string", required: true, enum: ["npm-package", "crypto-token"], desc: "research subject type" },
        { name: "subject", type: "string", required: true, desc: "npm package name or CoinGecko coin id" },
        { name: "maxPriceDem", type: "number", required: true, min: 1, max: 10, desc: "inclusive reserve price ceiling" },
      ],
      sampleInput: { kind: "npm-package", subject: "express", maxPriceDem: 5, paymentRail: "pay-dem" },
    }],
    timing: { healthyMinSec: 210, healthyMaxSec: 300, hardTimeoutSec: 480, protocolFloorSec: 120 },
    executionControl: { model: "server-orchestrated", interactiveConfirmation: false },
    buyerControl: {
      model: "gateway-custodied-demo",
      acceptsExternalDacsIdentity: false,
      acceptsExternalPaymentSigner: false,
    },
    paymentRails: ["pay-dem"],
    implementationStatus: "provisioning",
    unavailableReason: "the stable DACS release and SDK 4.0.14 model the winning bidder as the paying buyer; DACS-3 v0.3 fixes reverse-tender roles on the draft next branch, but this remains disabled until that contract is released and implemented by the SDK",
  },
] as const;

export function procurementProfile(id: string): ProcurementProfile | undefined {
  return PROCUREMENT_PROFILES.find((profile) => profile.id === id);
}
