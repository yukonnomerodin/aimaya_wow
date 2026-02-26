using System.ComponentModel.DataAnnotations;

namespace Adapter.WorldGateway;

internal enum BridgeStage
{
    PRE_AUTH = 0,
    AUTH_SESSION_BRIDGED = 1,
    ENTER_ENCRYPTED_SENT = 2,
    WORLD_CRYPT_ACTIVE = 3,
    BOOTSTRAP_FLUSHED = 4,
    CHAR_ENUM_REQUESTED = 5,
    CHAR_ENUM_RECEIVED = 6
}

internal readonly record struct HandshakeBaseline(
    string ScenarioId,
    string ClientBuild,
    string RealmConfig,
    string AccountIdentity,
    string AckPolicy,
    int PassThreshold,
    bool DeterministicReplayEnabled,
    string FailureClassTarget,
    string ActiveLayer,
    string ParityAxis,
    string BaselineTimestampUtc);

internal readonly record struct StageTransitionEvent(
    string TimestampUtc,
    BridgeStage FromStage,
    BridgeStage ToStage,
    string Reason);

internal readonly record struct TemporalInvariantResult(
    string Name,
    bool Passed,
    string Expected,
    string Actual,
    string TimestampUtc);

internal readonly record struct FirstDivergenceRecord(
    int? Offset,
    string Layer,
    string ParityAxis,
    string? ExpectedBytes,
    string? ActualBytes,
    string? SourcePath,
    string TimestampUtc);

internal readonly record struct NegativeEvidenceRow(
    string HypothesisId,
    string Layer,
    string ParityAxis,
    string SingleChangedVariable,
    string ExpectedObservable,
    string ActualObservable,
    string FailureClass,
    string Decision,
    string NextIsolationVariable,
    string TimestampUtc,
    string ScenarioId,
    string RunArtifactPath);

internal enum AckPolicyMode
{
    Auto,
    Gate,
    NonBlocking
}

internal static class AckPolicyResolver
{
    public static AckPolicyMode Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return AckPolicyMode.Auto;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "auto" => AckPolicyMode.Auto,
            "gate" => AckPolicyMode.Gate,
            "nogate" => AckPolicyMode.NonBlocking,
            "nonblocking" => AckPolicyMode.NonBlocking,
            "non_blocking" => AckPolicyMode.NonBlocking,
            _ => AckPolicyMode.Auto
        };
    }

    public static bool ResolveWaitForAckGate(AckPolicyMode mode, bool worldProxyAckGateDefault)
    {
        return mode switch
        {
            AckPolicyMode.Gate => true,
            AckPolicyMode.NonBlocking => false,
            _ => worldProxyAckGateDefault
        };
    }
}

public sealed class ProtocolEngineeringOptions
{
    public const string SectionName = "ProtocolEngineering";

    [Required]
    public string ScenarioId { get; init; } = "M1_CHAR_ENUM";

    [Range(1, 200)]
    public int PassThreshold { get; init; } = 20;

    [Required]
    public string AckPolicy { get; init; } = "auto";

    [Required]
    public string AckPolicyDecisionPath { get; init; } = "docs/handshake/matrix/ack_policy_decision.json";

    public bool DeterministicReplayEnabled { get; init; } = true;

    [Required]
    public string HypothesisId { get; init; } = "M1-SEED-000";

    [Required]
    public string SingleChangedVariable { get; init; } = "baseline_freeze_only";

    [Required]
    public string ExpectedObservable { get; init; } = "Reach CHAR_ENUM_RECEIVED without reason=3/24/no ACK";

    [Required]
    public string NextIsolationVariable { get; init; } = "length_header_opcode_payload_crypto";

    [Required]
    public string FailureClassTarget { get; init; } = "reason=24";

    [Required]
    public string ActiveLayer { get; init; } = "State";

    [Required]
    public string ParityAxis { get; init; } = "state-machine parity";

    public bool StrictStageEnforcement { get; init; } = true;

    [Required]
    public string ClientBuild { get; init; } = "12.0.1.66102";

    [Required]
    public string RealmConfig { get; init; } = "acore-3.3.5a";

    [Required]
    public string AccountIdentity { get; init; } = "account_id:552";
}
