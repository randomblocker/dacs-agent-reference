/**
 * Auditor-specific DACS-2 policy.
 *
 * The seller signs a small researcher profile into its DACS-1 IdentityBundle.
 * During Identify/Vet the buyer independently resolves the seller's Demos CCI
 * GitHub binding and records that observation, plus any previously verified
 * DACS-5 audit history, in its signed CompositeVerificationRecord.
 */
import {
  createVetRecord,
  verifyVetRecord,
  type BundleRequirement,
  type CompositeVerificationRecord,
  type DacsParty,
  type IdentityBundle,
  type Listing,
  type ResolvePublicKey,
  type VerifySignature,
} from "./standard-profile.js";

export const SECURITY_RESEARCHER_PROFILE_KEY = "securityResearcher";
export const SECURITY_RESEARCHER_POLICY = "dacs-security-researcher-v1";

export interface SecurityResearcherProfile {
  profileVersion: "1";
  github: string;
  operatorClaim: string;
}

export interface SecurityResearcherHistory {
  completedAudits: number;
  latestBundleRef?: string;
}

export interface SecurityResearcherVetEvidence {
  profile: SecurityResearcherProfile;
  boundGithub: string | null;
  history: SecurityResearcherHistory;
}

const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

export function normalizeResearcherGithub(value: string): string {
  const github = value.trim().replace(/^@/, "");
  if (!GITHUB_LOGIN.test(github)) throw new Error("security researcher GitHub login is invalid");
  return github.toLowerCase();
}

export function securityResearcherIdentityMetadata(input: {
  github: string;
  operatorClaim: string;
}): Record<string, unknown> {
  if (!input.operatorClaim) throw new Error("security researcher operator claim is required");
  return {
    [SECURITY_RESEARCHER_PROFILE_KEY]: {
      profileVersion: "1",
      github: normalizeResearcherGithub(input.github),
      operatorClaim: input.operatorClaim,
    },
  };
}

/** Read the profile from metadata covered by the seller's listing signature. */
export function securityResearcherProfileFromListing(listing: Listing): SecurityResearcherProfile | null {
  const identity = listing?.seller?.identity;
  if (!identity || !Array.isArray(identity.claims) || typeof identity.presentedBy !== "string") return null;
  const primary = identity.claims.find((claim) => claim.ref === identity.presentedBy);
  const value = primary?.metadata?.[SECURITY_RESEARCHER_PROFILE_KEY];
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (raw.profileVersion !== "1" || typeof raw.github !== "string" || typeof raw.operatorClaim !== "string") return null;
  let github: string;
  try {
    github = normalizeResearcherGithub(raw.github);
  } catch {
    return null;
  }
  if (raw.operatorClaim !== identity.presentedBy) return null;
  return { profileVersion: "1", github, operatorClaim: raw.operatorClaim };
}

/**
 * The requirement hash commits the CVR to the exact signed researcher profile.
 * GitHub control is evaluated from CCI and carried as a supplementary signal;
 * the DID claim itself is already proved by the nonce-bound presentation.
 */
export function securityResearcherRequirement(profile: SecurityResearcherProfile): BundleRequirement {
  return {
    requirementVersion: "1",
    required: [{
      scheme: "did",
      verificationRequired: false,
      parameters: {
        policy: SECURITY_RESEARCHER_POLICY,
        github: profile.github,
        operatorClaim: profile.operatorClaim,
      },
    }],
    preferredPresentation: "per-claim",
    primaryClaimSelector: "did",
  };
}

export async function createSecurityResearcherVetRecord(
  verifier: DacsParty,
  input: {
    jobId: string;
    bundle: IdentityBundle;
    profile: SecurityResearcherProfile;
    boundGithub: string | null;
    history?: SecurityResearcherHistory;
    generatedAt?: number;
  },
): Promise<CompositeVerificationRecord> {
  if (input.bundle.presentedBy !== input.profile.operatorClaim) {
    throw new Error("security researcher profile does not identify the presented seller");
  }
  const observedAt = input.generatedAt ?? Date.now();
  const boundGithub = input.boundGithub ? normalizeResearcherGithub(input.boundGithub) : null;
  const history = input.history ?? { completedAudits: 0 };
  if (!Number.isSafeInteger(history.completedAudits) || history.completedAudits < 0) {
    throw new Error("security researcher DACS-5 history is invalid");
  }
  const cciMatches = boundGithub === input.profile.github;
  return createVetRecord(verifier, {
    jobId: input.jobId,
    bundle: input.bundle,
    requirement: securityResearcherRequirement(input.profile),
    supplementary: [
      {
        source: "identity-presentation",
        signalType: "nonce-bound-key-control",
        value: "pass",
        observedAt,
      },
      {
        source: "cci-web2",
        signalType: "github-control",
        value: boundGithub ?? "unbound",
        observedAt,
      },
      {
        source: "dacs-5",
        signalType: "verified-completed-audits",
        value: history.completedAudits,
        observedAt,
      },
      ...(history.latestBundleRef ? [{
        source: "dacs-5",
        signalType: "latest-verified-bundle",
        value: history.latestBundleRef,
        observedAt,
      }] : []),
    ],
    overallDecision: cciMatches ? "pass" : "fail",
    generatedAt: observedAt,
  });
}

export async function verifySecurityResearcherVetRecord(
  record: CompositeVerificationRecord,
  input: {
    jobId: string;
    bundle: IdentityBundle;
    profile: SecurityResearcherProfile;
    verifier: string;
    resolvePublicKey: ResolvePublicKey;
    verify: VerifySignature;
  },
): Promise<boolean> {
  if (!(await verifyVetRecord(record, {
    jobId: input.jobId,
    bundle: input.bundle,
    requirement: securityResearcherRequirement(input.profile),
    verifier: input.verifier,
    resolvePublicKey: input.resolvePublicKey,
    verify: input.verify,
  }))) return false;
  const keyControl = record.supplementary.find((signal) =>
    signal.source === "identity-presentation" && signal.signalType === "nonce-bound-key-control");
  const github = record.supplementary.find((signal) =>
    signal.source === "cci-web2" && signal.signalType === "github-control");
  const completed = record.supplementary.find((signal) =>
    signal.source === "dacs-5" && signal.signalType === "verified-completed-audits");
  return keyControl?.value === "pass"
    && github?.value === input.profile.github
    && typeof completed?.value === "number"
    && Number.isSafeInteger(completed.value)
    && completed.value >= 0;
}

export function securityResearcherVetEvidence(
  record: CompositeVerificationRecord,
  profile: SecurityResearcherProfile,
): SecurityResearcherVetEvidence | null {
  const github = record.supplementary.find((signal) =>
    signal.source === "cci-web2" && signal.signalType === "github-control");
  const completed = record.supplementary.find((signal) =>
    signal.source === "dacs-5" && signal.signalType === "verified-completed-audits");
  const latest = record.supplementary.find((signal) =>
    signal.source === "dacs-5" && signal.signalType === "latest-verified-bundle");
  if (github?.value !== profile.github || typeof completed?.value !== "number") return null;
  return {
    profile,
    boundGithub: profile.github,
    history: {
      completedAudits: completed.value,
      ...(typeof latest?.value === "string" ? { latestBundleRef: latest.value } : {}),
    },
  };
}
