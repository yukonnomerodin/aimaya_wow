namespace Adapter.WorldGateway;

internal sealed record HandshakeLabReport
{
    public string TimestampUtc { get; init; } = DateTimeOffset.UtcNow.ToString("O");
    public string ScenarioId { get; init; } = "M1_CHAR_ENUM";
    public int PassThreshold { get; init; } = 20;
    public string AckPolicy { get; init; } = "auto";
    public bool DeterministicReplayEnabled { get; init; } = true;
    public string HypothesisId { get; init; } = "M1-SEED-000";
    public string SingleChangedVariable { get; init; } = "baseline_freeze_only";
    public string ExpectedObservable { get; init; } = "Reach CHAR_ENUM_RECEIVED without reason=3/24/no ACK";
    public string NextIsolationVariable { get; init; } = "length_header_opcode_payload_crypto";
    public string FailureClassTarget { get; init; } = "reason=24";
    public string FailureClass { get; init; } = "inconclusive";
    public string ActiveLayer { get; init; } = "State";
    public string ParityAxis { get; init; } = "state-machine parity";
    public uint ConnectionId { get; init; }
    public bool AckObserved { get; init; }
    public long? AckConfirmedElapsedMs { get; init; }
    public uint? DisconnectReason { get; init; }
    public long? DisconnectElapsedMs { get; init; }
    public int? TimeoutPendingBytes { get; init; }
    public string? TimeoutPendingRetail { get; init; }
    public string? EnterEncryptedPayloadHexPath { get; init; }
    public string? EnterEncryptedPayloadMetadataPath { get; init; }
    public string? EnterEncryptedPayloadDiffPath { get; init; }
    public bool SignatureFirst { get; init; }
    public int RegionGroup { get; init; }
    public bool IncludeRegionGroup { get; init; } = true;
    public bool EnterEncryptedEnabled { get; init; }
    public bool EnterEncryptedEnabledAsByte { get; init; }
    public string EnterEncryptedOpcode { get; init; } = "0x00490004";
    public bool EnterEncryptedPreferBnetKeyData { get; init; } = true;
    public int AckTimeoutMs { get; init; }
    public string AwaitingRetailOpcodes { get; init; } = "<none>";
    public long BytesClientToWorld { get; init; }
    public long BytesWorldToClient { get; init; }
    public string ConnectionOpenedAtUtc { get; init; } = string.Empty;
    public string ConnectionClosedAtUtc { get; init; } = string.Empty;
    public long ConnectionDurationMs { get; init; }
    public string CurrentStage { get; init; } = BridgeStage.PRE_AUTH.ToString();
    public bool CharEnumRequested { get; init; }
    public bool CharEnumReceived { get; init; }
    public string Boundary { get; init; } = "<none>";
    public string DeferredFirst { get; init; } = "<none>";
    public ulong? DeferredFirstServerCounter { get; init; }
    public string? DeferredFirstPlainSha256 { get; init; }
    public string? DeferredFirstProtectedSha256 { get; init; }
    public string? DeferredFirstProtectedTagHex { get; init; }
    public string? DeferredFirstParityStatus { get; init; }
    public int? DeferredFirstParityDiffOffset { get; init; }
    public string? DeferredFirstParityExpectedBytes { get; init; }
    public string? DeferredFirstParityActualBytes { get; init; }
    public string? DeferredFirstParityFixturePath { get; init; }
    public string DeferredFlushPath { get; init; } = "<none>";
    public uint? PostAckNonAckTriggerOpcode { get; init; }
    public long? PostAckNonAckTriggerWaitMs { get; init; }
    public bool RunValid { get; init; }
    public string RunValidReason { get; init; } = "missing_observables";
    public int? FirstDivergenceOffset { get; init; }
    public string? FirstDivergenceExpectedBytes { get; init; }
    public string? FirstDivergenceActualBytes { get; init; }
    public string? FirstDivergenceSourcePath { get; init; }
    public IReadOnlyList<StageTransitionEvent> StageTransitions { get; init; } = Array.Empty<StageTransitionEvent>();
    public IReadOnlyList<TemporalInvariantResult> TemporalInvariants { get; init; } = Array.Empty<TemporalInvariantResult>();
    public HandshakeBaseline? Baseline { get; init; }

    public static HandshakeLabReport Create(
        uint connectionId,
        WorldProxyOptions options,
        ProtocolEngineeringOptions protocolOptions,
        WorldProxyBridgeState state,
        DateTimeOffset openedAt,
        DateTimeOffset closedAt,
        long bytesClientToWorld,
        long bytesWorldToClient)
    {
        state.TryGetAckConfirmedElapsedMs(out long ackElapsedMs);
        bool hasDisconnect = state.TryGetDisconnect(out uint disconnectReason, out long disconnectElapsedMs);
        bool hasTimeout = state.TryGetAckTimeout(out int timeoutPendingBytes, out string timeoutPendingRetail);
        bool hasProofArtifacts = state.TryGetProofPackArtifacts(out string proofHexPath, out string proofMetadataPath, out string proofDiffPath);
        bool hasBaseline = state.TryGetBaseline(out HandshakeBaseline baseline);
        bool hasFirstDivergence = state.TryGetFirstDivergence(out FirstDivergenceRecord firstDivergence);
        bool hasBoundary = state.TryGetDeferredFrameBoundary(out int deferredSent, out int deferredTotal);
        bool hasDeferredFirst = state.TryGetFirstDeferredFrame(out uint deferredOpcode, out int deferredBodyLength, out int deferredFrameBytes);
        bool hasDeferredEvidence = state.TryGetFirstDeferredFrameEvidence(
            out ulong deferredServerCounter,
            out string deferredPlainSha256,
            out string deferredProtectedSha256,
            out string deferredProtectedTagHex);
        bool hasDeferredParity = state.TryGetFirstDeferredFrameParity(
            out string deferredParityStatus,
            out int? deferredParityDiffOffset,
            out string? deferredParityExpectedBytes,
            out string? deferredParityActualBytes,
            out string? deferredParityFixturePath);
        bool hasPostAckTriggerOpcode = state.TryGetPostAckNonAckBootstrapTriggerOpcode(out uint postAckTriggerOpcode);
        bool hasPostAckTriggerWait = state.TryGetPostAckNonAckBootstrapTriggerWait(out long postAckTriggerWaitMs);
        string deferredFlushPath = state.DeferredFlushPath;
        BridgeStage currentStage = state.CurrentStage;
        string failureClass = state.ResolveFailureClass();
        string boundary = hasBoundary ? $"{deferredSent}/{deferredTotal}" : "<none>";
        string deferredFirst = hasDeferredFirst
            ? $"0x{deferredOpcode:X8}(body={deferredBodyLength},frame={deferredFrameBytes})"
            : "<none>";
        bool runValid =
            state.AckObserved &&
            currentStage >= BridgeStage.WORLD_CRYPT_ACTIVE &&
            hasBoundary &&
            hasDeferredFirst &&
            hasDeferredEvidence;
        string runValidReason = runValid
            ? "ok"
            : $"ack={state.AckObserved};stage={currentStage};boundary={boundary};deferred_first={deferredFirst};deferred_flush_path={deferredFlushPath};deferred_first_sha={(hasDeferredEvidence ? "present" : "missing")}";

        return new HandshakeLabReport
        {
            ScenarioId = protocolOptions.ScenarioId,
            PassThreshold = protocolOptions.PassThreshold,
            AckPolicy = protocolOptions.AckPolicy,
            DeterministicReplayEnabled = protocolOptions.DeterministicReplayEnabled,
            HypothesisId = protocolOptions.HypothesisId,
            SingleChangedVariable = protocolOptions.SingleChangedVariable,
            ExpectedObservable = protocolOptions.ExpectedObservable,
            NextIsolationVariable = protocolOptions.NextIsolationVariable,
            FailureClassTarget = protocolOptions.FailureClassTarget,
            FailureClass = failureClass,
            ActiveLayer = state.ActiveLayer,
            ParityAxis = state.ParityAxis,
            ConnectionId = connectionId,
            AckObserved = state.AckObserved,
            AckConfirmedElapsedMs = ackElapsedMs >= 0 ? ackElapsedMs : null,
            DisconnectReason = hasDisconnect ? disconnectReason : null,
            DisconnectElapsedMs = hasDisconnect && disconnectElapsedMs >= 0 ? disconnectElapsedMs : null,
            TimeoutPendingBytes = hasTimeout ? timeoutPendingBytes : null,
            TimeoutPendingRetail = hasTimeout ? timeoutPendingRetail : null,
            EnterEncryptedPayloadHexPath = hasProofArtifacts ? proofHexPath : null,
            EnterEncryptedPayloadMetadataPath = hasProofArtifacts ? proofMetadataPath : null,
            EnterEncryptedPayloadDiffPath = hasProofArtifacts ? proofDiffPath : null,
            SignatureFirst = options.EnterEncryptedModeSignatureFirst,
            RegionGroup = options.EnterEncryptedModeRegionGroup,
            IncludeRegionGroup = options.EnterEncryptedModeIncludeRegionGroup,
            EnterEncryptedEnabled = options.EnterEncryptedModeEnabled,
            EnterEncryptedEnabledAsByte = options.EnterEncryptedModeEnabledAsByte,
            EnterEncryptedOpcode = options.EnterEncryptedModeOpcode,
            EnterEncryptedPreferBnetKeyData = options.EnterEncryptedModePreferBnetKeyData,
            AckTimeoutMs = options.EnterEncryptedModeAckTimeoutMs,
            AwaitingRetailOpcodes = state.AwaitingRetailOpcodes,
            BytesClientToWorld = bytesClientToWorld,
            BytesWorldToClient = bytesWorldToClient,
            ConnectionOpenedAtUtc = openedAt.ToString("O"),
            ConnectionClosedAtUtc = closedAt.ToString("O"),
            ConnectionDurationMs = Math.Max(0, (long)(closedAt - openedAt).TotalMilliseconds),
            CurrentStage = currentStage.ToString(),
            CharEnumRequested = currentStage >= BridgeStage.CHAR_ENUM_REQUESTED,
            CharEnumReceived = currentStage >= BridgeStage.CHAR_ENUM_RECEIVED,
            Boundary = boundary,
            DeferredFirst = deferredFirst,
            DeferredFirstServerCounter = hasDeferredEvidence ? deferredServerCounter : null,
            DeferredFirstPlainSha256 = hasDeferredEvidence ? deferredPlainSha256 : null,
            DeferredFirstProtectedSha256 = hasDeferredEvidence ? deferredProtectedSha256 : null,
            DeferredFirstProtectedTagHex = hasDeferredEvidence ? deferredProtectedTagHex : null,
            DeferredFirstParityStatus = hasDeferredParity ? deferredParityStatus : null,
            DeferredFirstParityDiffOffset = hasDeferredParity ? deferredParityDiffOffset : null,
            DeferredFirstParityExpectedBytes = hasDeferredParity ? deferredParityExpectedBytes : null,
            DeferredFirstParityActualBytes = hasDeferredParity ? deferredParityActualBytes : null,
            DeferredFirstParityFixturePath = hasDeferredParity ? deferredParityFixturePath : null,
            DeferredFlushPath = deferredFlushPath,
            PostAckNonAckTriggerOpcode = hasPostAckTriggerOpcode ? postAckTriggerOpcode : null,
            PostAckNonAckTriggerWaitMs = hasPostAckTriggerWait ? postAckTriggerWaitMs : null,
            RunValid = runValid,
            RunValidReason = runValidReason,
            FirstDivergenceOffset = hasFirstDivergence ? firstDivergence.Offset : null,
            FirstDivergenceExpectedBytes = hasFirstDivergence ? firstDivergence.ExpectedBytes : null,
            FirstDivergenceActualBytes = hasFirstDivergence ? firstDivergence.ActualBytes : null,
            FirstDivergenceSourcePath = hasFirstDivergence ? firstDivergence.SourcePath : null,
            StageTransitions = state.GetStageTransitions(),
            TemporalInvariants = state.GetTemporalInvariants(),
            Baseline = hasBaseline ? baseline : null
        };
    }
}

internal readonly record struct AuthResponseFuzzMutation(
    bool Enabled,
    string Plan,
    int Iteration,
    int LeadingZeroBits,
    int AccountDataPermutationVariant,
    uint? OpcodeOverride,
    bool UseShortRealmId,
    bool SwapExpansionAndBillingFlags,
    bool InsertPaddingU32AfterBitBlock,
    string MutationLabel)
{
    public static AuthResponseFuzzMutation Disabled =>
        new(
            Enabled: false,
            Plan: "none",
            Iteration: 0,
            LeadingZeroBits: 0,
            AccountDataPermutationVariant: -1,
            OpcodeOverride: null,
            UseShortRealmId: false,
            SwapExpansionAndBillingFlags: false,
            InsertPaddingU32AfterBitBlock: false,
            MutationLabel: "disabled");
}

