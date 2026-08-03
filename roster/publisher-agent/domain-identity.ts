import type { DomainIdentityBinding } from "./types.js";

export function canonicalPublisherDomain(value: string): string {
  if (value !== value.trim() || !value) throw new Error("publisher domain must be non-empty canonical text");
  let url: URL;
  try { url = new URL(`https://${value}`); } catch { throw new Error("publisher domain is invalid"); }
  const hostname = url.hostname.toLowerCase();
  if (value !== hostname || url.pathname !== "/" || url.port || url.username || url.password
    || hostname === "localhost" || hostname.endsWith(".local") || !hostname.includes(".")) {
    throw new Error("publisher domain must be a lowercase DNS hostname without URL components");
  }
  return hostname;
}

export function validateDomainIdentityBinding(input: DomainIdentityBinding): DomainIdentityBinding {
  const hostname = canonicalPublisherDomain(input.hostname);
  if (input.claim !== `web2:domain:${hostname}`) {
    throw new Error("publisher domain claim must match the current Demos GCR web2.domain representation");
  }
  if (input.proofUrl !== `https://${hostname}/.well-known/demos-cci.txt`) {
    throw new Error("publisher domain proof URL is not the Demos well-known URL");
  }
  if (!/^did:demos:agent:[0-9a-f]{64}$/i.test(input.gcrOwner)) throw new Error("publisher GCR owner DID is invalid");
  return { ...input, hostname };
}

export function domainIdentityMetadata(input: DomainIdentityBinding): Record<string, unknown> {
  const binding = validateDomainIdentityBinding(input);
  return {
    domainIdentity: {
      ...binding,
      source: "demos-gcr-web2.domain",
      canonicalClaimPending: `domain:${binding.hostname}`,
      standardsIssue: "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/275",
    },
  };
}
