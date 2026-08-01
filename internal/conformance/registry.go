package conformance

// CaseID is one closed conformance assertion group.
type CaseID string

// ProofLayer separates actual-host, synthetic-lifecycle, and actual-GitHub
// evidence. A result from one layer cannot satisfy another layer's case.
type ProofLayer string

const (
	LayerActualHostImmutable   ProofLayer = "actual-host-immutable"
	LayerSyntheticLifecycle    ProofLayer = "synthetic-lifecycle"
	LayerActualGitHubTransport ProofLayer = "actual-github-transport"
)

const (
	CaseHostProfile             CaseID = "host-profile"
	CaseNamespaceBaseline       CaseID = "namespace-baseline"
	CaseBrokerEgress            CaseID = "broker-egress"
	CaseMountAndSecretIsolation CaseID = "mount-and-secret-isolation"
	CaseSandbox                 CaseID = "runner-sandbox"
	CaseRunnerPayload           CaseID = "runner-payload"
	CaseSyntheticOneJob         CaseID = "synthetic-one-job"
	CaseCleanupMatrix           CaseID = "cleanup-matrix"
	CaseReclamationSeries       CaseID = "reclamation-series"
	CaseProxyToolCompatibility  CaseID = "proxy-tool-compatibility"
	CaseSeedIsolation           CaseID = "seed-isolation"
	CaseWatchdogRecovery        CaseID = "watchdog-recovery"
	CaseLegacyFenceRecovery     CaseID = "legacy-fence-recovery"
	CaseNoncancellableShutdown  CaseID = "noncancellable-shutdown"
	CaseActualGitHubTransport   CaseID = "actual-github-transport"
)

// ActualHostCaseID is a closed dispatch key for actual-host evidence.
type ActualHostCaseID uint8

const (
	ActualHostProfile ActualHostCaseID = iota + 1
	ActualNamespaceBaseline
	ActualBrokerEgress
	ActualMountAndSecretIsolation
	ActualRunnerSandbox
	ActualRunnerPayload
	ActualProxyToolCompatibility
)

// SyntheticCaseID is a closed dispatch key for synthetic lifecycle evidence.
type SyntheticCaseID uint8

const (
	SyntheticOneJob SyntheticCaseID = iota + 1
	SyntheticCleanupMatrix
	SyntheticReclamationSeries
	SyntheticSeedIsolation
	SyntheticWatchdogRecovery
	SyntheticLegacyFenceRecovery
	SyntheticNoncancellableShutdown
)

type caseDefinition struct {
	id        CaseID
	layer     ProofLayer
	actual    ActualHostCaseID
	synthetic SyntheticCaseID
}

var requiredCaseRegistry = [...]caseDefinition{
	{id: CaseHostProfile, layer: LayerActualHostImmutable, actual: ActualHostProfile},
	{id: CaseNamespaceBaseline, layer: LayerActualHostImmutable, actual: ActualNamespaceBaseline},
	{id: CaseBrokerEgress, layer: LayerActualHostImmutable, actual: ActualBrokerEgress},
	{id: CaseMountAndSecretIsolation, layer: LayerActualHostImmutable, actual: ActualMountAndSecretIsolation},
	{id: CaseSandbox, layer: LayerActualHostImmutable, actual: ActualRunnerSandbox},
	{id: CaseRunnerPayload, layer: LayerActualHostImmutable, actual: ActualRunnerPayload},
	{id: CaseSyntheticOneJob, layer: LayerSyntheticLifecycle, synthetic: SyntheticOneJob},
	{id: CaseCleanupMatrix, layer: LayerSyntheticLifecycle, synthetic: SyntheticCleanupMatrix},
	{id: CaseReclamationSeries, layer: LayerSyntheticLifecycle, synthetic: SyntheticReclamationSeries},
	{id: CaseProxyToolCompatibility, layer: LayerActualHostImmutable, actual: ActualProxyToolCompatibility},
	{id: CaseSeedIsolation, layer: LayerSyntheticLifecycle, synthetic: SyntheticSeedIsolation},
	{id: CaseWatchdogRecovery, layer: LayerSyntheticLifecycle, synthetic: SyntheticWatchdogRecovery},
	{id: CaseLegacyFenceRecovery, layer: LayerSyntheticLifecycle, synthetic: SyntheticLegacyFenceRecovery},
	{id: CaseNoncancellableShutdown, layer: LayerSyntheticLifecycle, synthetic: SyntheticNoncancellableShutdown},
	{id: CaseActualGitHubTransport, layer: LayerActualGitHubTransport},
}

// RequiredCases returns a defensive copy of the exact V1 case order.
func RequiredCases() []CaseID {
	cases := make([]CaseID, len(requiredCaseRegistry))
	for index, definition := range requiredCaseRegistry {
		cases[index] = definition.id
	}
	return cases
}

// RequiredLayer returns the registry-owned proof layer for one exact case.
func RequiredLayer(id CaseID) (ProofLayer, bool) {
	definition, ok := lookupCase(id)
	if !ok {
		return "", false
	}
	return definition.layer, true
}

func lookupCase(id CaseID) (caseDefinition, bool) {
	for _, definition := range requiredCaseRegistry {
		if definition.id == id {
			return definition, true
		}
	}
	return caseDefinition{}, false
}

func lookupActualCase(id ActualHostCaseID) (caseDefinition, bool) {
	if id == 0 {
		return caseDefinition{}, false
	}
	for _, definition := range requiredCaseRegistry {
		if definition.actual == id {
			return definition, true
		}
	}
	return caseDefinition{}, false
}

func lookupSyntheticCase(id SyntheticCaseID) (caseDefinition, bool) {
	if id == 0 {
		return caseDefinition{}, false
	}
	for _, definition := range requiredCaseRegistry {
		if definition.synthetic == id {
			return definition, true
		}
	}
	return caseDefinition{}, false
}
