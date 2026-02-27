using System.IO;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void ValidateProtocolExperimentContractOrThrow()
    {
        if (string.IsNullOrWhiteSpace(_protocolOptions.HypothesisId) ||
            string.IsNullOrWhiteSpace(_protocolOptions.SingleChangedVariable) ||
            string.IsNullOrWhiteSpace(_protocolOptions.ExpectedObservable) ||
            string.IsNullOrWhiteSpace(_protocolOptions.NextIsolationVariable))
        {
            throw new InvalidOperationException(
                "ProtocolEngineering experiment contract is incomplete. Set HypothesisId, SingleChangedVariable, ExpectedObservable, and NextIsolationVariable before running.");
        }

        string matrixPath = Path.Combine(WorldGatewayPathResolver.ResolveProofPackRoot(_options), "matrix", "negative_evidence.csv");
        if (!File.Exists(matrixPath))
        {
            return;
        }

        if (MatrixPolicyGuard.TryFindRejectedChangeSet(matrixPath, _protocolOptions.SingleChangedVariable, out string? rejectedHypothesis))
        {
            throw new InvalidOperationException(
                $"Rejected change set replay is blocked by matrix policy. SingleChangedVariable='{_protocolOptions.SingleChangedVariable}', RejectedHypothesis='{rejectedHypothesis ?? "<unknown>"}', Matrix='{matrixPath}'.");
        }
    }
}
