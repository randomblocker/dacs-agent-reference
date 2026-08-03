import {
  PINNED_DEMOSWORK_CAPABILITIES,
  assertLiveAtomicDacsSupported,
  type DemosWorkCapabilities,
} from "./capabilities.js";

export type DemosWorkRolloutMode = "disabled" | "shadow" | "live";

export type DemosWorkRoute = {
  execution: "multi-transaction" | "atomic-demoswork";
  shadowValidation: boolean;
};

export function parseDemosWorkRolloutMode(value: string | undefined): DemosWorkRolloutMode {
  if (value === undefined || value === "" || value === "disabled") return "disabled";
  if (value === "shadow" || value === "live") return value;
  throw new Error("DACS_DEMOSWORK_ATOMIC_MODE must be disabled, shadow, or live");
}

/**
 * Selection is fail-closed. Shadow mode always retains the normative
 * multi-transaction path; live mode cannot be selected until the supplied SDK
 * and node capability contract proves every load-bearing atomic guarantee.
 */
export function selectDemosWorkRoute(
  mode: DemosWorkRolloutMode,
  capabilities: DemosWorkCapabilities = PINNED_DEMOSWORK_CAPABILITIES,
): DemosWorkRoute {
  if (mode === "disabled") return { execution: "multi-transaction", shadowValidation: false };
  if (mode === "shadow") return { execution: "multi-transaction", shadowValidation: true };
  assertLiveAtomicDacsSupported(capabilities);
  return { execution: "atomic-demoswork", shadowValidation: false };
}
