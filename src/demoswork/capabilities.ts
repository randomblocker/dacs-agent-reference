export type DemosWorkCapabilities = {
  sdkVersion: string;
  submit: boolean;
  nativeTransfer: boolean;
  storageProgramPut: boolean;
  multiPartyAuthorization: boolean;
  atomicNativeRollback: "verified" | "unverified";
  stableWorkId: boolean;
  authoritativeReceipt: boolean;
  esmCompatibleOnNode22: boolean;
};

/**
 * Capabilities observed in the pinned DACS SDK's demosdk 4.0.16 dependency.
 * This is deliberately explicit: absence of any load-bearing capability keeps
 * live DACS atomic submission disabled.
 */
export const PINNED_DEMOSWORK_CAPABILITIES: DemosWorkCapabilities = {
  sdkVersion: "4.0.16",
  submit: true,
  nativeTransfer: true,
  storageProgramPut: false,
  multiPartyAuthorization: false,
  atomicNativeRollback: "unverified",
  stableWorkId: false,
  authoritativeReceipt: false,
  esmCompatibleOnNode22: false,
};

export function missingAtomicDacsCapabilities(capabilities: DemosWorkCapabilities): string[] {
  const missing: string[] = [];
  if (!capabilities.submit) missing.push("Demos Work submission");
  if (!capabilities.nativeTransfer) missing.push("native DEM transfer step");
  if (!capabilities.storageProgramPut) missing.push("StorageProgram Work step");
  if (!capabilities.multiPartyAuthorization) missing.push("operation-level multi-party authorization");
  if (capabilities.atomicNativeRollback !== "verified") missing.push("verified atomic rollback for Demos-native state");
  if (!capabilities.stableWorkId) missing.push("stable pre-submission workId");
  if (!capabilities.authoritativeReceipt) missing.push("authoritative operation receipt");
  if (!capabilities.esmCompatibleOnNode22) missing.push("Node 22 ESM-compatible Demos Work exports");
  return missing;
}

export function assertLiveAtomicDacsSupported(capabilities = PINNED_DEMOSWORK_CAPABILITIES): void {
  const missing = missingAtomicDacsCapabilities(capabilities);
  if (missing.length) {
    throw new Error(`live atomic DACS Demos Work is disabled; missing: ${missing.join(", ")}`);
  }
}
