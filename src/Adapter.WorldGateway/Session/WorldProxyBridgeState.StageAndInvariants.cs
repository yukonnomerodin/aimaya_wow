using System.Globalization;
using System.Text;

namespace Adapter.WorldGateway;

internal sealed partial class WorldProxyBridgeState
{
    public BridgeStage CurrentStage
    {
        get
        {
            lock (_stageSync)
            {
                return _currentStage;
            }
        }
    }

    public void SetBaseline(HandshakeBaseline baseline)
    {
        lock (_stageSync)
        {
            _baseline = baseline;
            _failureClassTarget = baseline.FailureClassTarget;
            _activeLayer = baseline.ActiveLayer;
            _parityAxis = baseline.ParityAxis;
        }
    }

    public void SetEvidenceContext(string layer, string parityAxis)
    {
        lock (_stageSync)
        {
            if (!string.IsNullOrWhiteSpace(layer))
            {
                _activeLayer = layer;
            }

            if (!string.IsNullOrWhiteSpace(parityAxis))
            {
                _parityAxis = parityAxis;
            }
        }
    }

    public bool TryGetBaseline(out HandshakeBaseline baseline)
    {
        lock (_stageSync)
        {
            if (_baseline is not null)
            {
                baseline = _baseline.Value;
                return true;
            }
        }

        baseline = default;
        return false;
    }

    public bool TryTransitionStage(BridgeStage nextStage, string reason)
    {
        lock (_stageSync)
        {
            BridgeStage current = _currentStage;
            if (nextStage == current)
            {
                return true;
            }

            if (!IsTransitionAllowed(current, nextStage))
            {
                MarkTemporalInvariantLocked(
                    name: "stage_transition_valid",
                    passed: false,
                    expected: $"{current} -> {nextStage} allowed",
                    actual: $"rejected transition ({reason})");
                return false;
            }

            _currentStage = nextStage;
            _stageTransitions.Add(
                new StageTransitionEvent(
                    TimestampUtc: DateTimeOffset.UtcNow.ToString("O"),
                    FromStage: current,
                    ToStage: nextStage,
                    Reason: reason));
            return true;
        }

    }

    public bool ValidateClientOpcode(uint opcode, bool strictEnforcement, out string? error)
    {
        error = null;
        lock (_stageSync)
        {
            if (opcode == WorldGatewayOpcodes.RetailCmsgEnterEncryptedModeAck && _currentStage < BridgeStage.ENTER_ENCRYPTED_SENT)
            {
                string actual = $"opcode=0x{opcode:X8} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "client_ack_after_enter_encrypted_sent",
                    passed: false,
                    expected: "ACK only after ENTER_ENCRYPTED_SENT",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected ACK opcode in stage {_currentStage}.";
                    return false;
                }
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgEnumCharacters && _currentStage < BridgeStage.BOOTSTRAP_FLUSHED)
            {
                string actual = $"opcode=0x{opcode:X8} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "client_char_enum_after_bootstrap_flushed",
                    passed: false,
                    expected: "CHAR_ENUM request only after BOOTSTRAP_FLUSHED",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected CMSG_ENUM_CHARACTERS in stage {_currentStage}.";
                    return false;
                }
            }
        }

        return true;
    }

    public bool ValidateServerOpcode(ushort opcode, bool strictEnforcement, out string? error)
    {
        error = null;
        lock (_stageSync)
        {
            if (opcode == WorldGatewayOpcodes.AcoreSmsgAuthResponse && _currentStage < BridgeStage.AUTH_SESSION_BRIDGED)
            {
                string actual = $"opcode=0x{opcode:X4} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "server_auth_response_after_auth_session_bridged",
                    passed: false,
                    expected: "SMSG_AUTH_RESPONSE only after AUTH_SESSION_BRIDGED",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected SMSG_AUTH_RESPONSE in stage {_currentStage}.";
                    return false;
                }
            }

            if (opcode == WorldGatewayOpcodes.AcoreSmsgCharEnum && _currentStage < BridgeStage.CHAR_ENUM_REQUESTED)
            {
                string actual = $"opcode=0x{opcode:X4} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "server_char_enum_after_char_enum_requested",
                    passed: false,
                    expected: "SMSG_CHAR_ENUM only after CHAR_ENUM_REQUESTED",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected SMSG_CHAR_ENUM in stage {_currentStage}.";
                    return false;
                }
            }
        }

        return true;
    }

    public void MarkTemporalInvariant(string name, bool passed, string expected, string actual)
    {
        lock (_stageSync)
        {
            MarkTemporalInvariantLocked(name, passed, expected, actual);
        }
    }

    public IReadOnlyList<StageTransitionEvent> GetStageTransitions()
    {
        lock (_stageSync)
        {
            return _stageTransitions.ToArray();
        }
    }

    public IReadOnlyList<TemporalInvariantResult> GetTemporalInvariants()
    {
        lock (_stageSync)
        {
            return _temporalInvariants.ToArray();
        }
    }

    public bool TryGetFirstDivergence(out FirstDivergenceRecord divergence)
    {
        lock (_stageSync)
        {
            if (_firstDivergence is not null)
            {
                divergence = _firstDivergence.Value;
                return true;
            }
        }

        divergence = default;
        return false;
    }

    public string FailureClassTarget
    {
        get
        {
            lock (_stageSync)
            {
                return _failureClassTarget ?? "<unknown>";
            }
        }
    }

    public string ActiveLayer
    {
        get
        {
            lock (_stageSync)
            {
                return _activeLayer ?? "<unknown>";
            }
        }
    }

    public string ParityAxis
    {
        get
        {
            lock (_stageSync)
            {
                return _parityAxis ?? "<unknown>";
            }
        }
    }

    public string ResolveFailureClass()
    {
        if (TryGetDisconnect(out uint reason, out _))
        {
            if (reason == 3)
            {
                return "reason=3";
            }

            if (reason == 24)
            {
                return "reason=24";
            }

            if (reason == 14)
            {
                return CurrentStage >= BridgeStage.CHAR_ENUM_RECEIVED
                    ? "none"
                    : "inconclusive";
            }

            return $"reason={reason}";
        }

        if (HasFailedInvariant("db_parity_gate"))
        {
            return "db_mismatch";
        }

        if (HasFailedInvariant("stage_transition_valid") ||
            HasFailedInvariant("client_ack_after_enter_encrypted_sent") ||
            HasFailedInvariant("client_char_enum_after_bootstrap_flushed") ||
            HasFailedInvariant("server_auth_response_after_auth_session_bridged") ||
            HasFailedInvariant("server_char_enum_after_char_enum_requested"))
        {
            return "reason=3";
        }

        if (TryGetAckTimeout(out _, out _))
        {
            return "no ACK";
        }

        return CurrentStage >= BridgeStage.CHAR_ENUM_RECEIVED ? "none" : "inconclusive";
    }

    private bool HasFailedInvariant(string invariantName)
    {
        lock (_stageSync)
        {
            foreach (TemporalInvariantResult invariant in _temporalInvariants)
            {
                if (!invariant.Passed &&
                    string.Equals(invariant.Name, invariantName, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsTransitionAllowed(BridgeStage current, BridgeStage next)
    {
        return current switch
        {
            BridgeStage.PRE_AUTH => next == BridgeStage.AUTH_SESSION_BRIDGED,
            BridgeStage.AUTH_SESSION_BRIDGED => next == BridgeStage.ENTER_ENCRYPTED_SENT,
            BridgeStage.ENTER_ENCRYPTED_SENT => next == BridgeStage.WORLD_CRYPT_ACTIVE || next == BridgeStage.BOOTSTRAP_FLUSHED,
            BridgeStage.WORLD_CRYPT_ACTIVE => next == BridgeStage.BOOTSTRAP_FLUSHED,
            BridgeStage.BOOTSTRAP_FLUSHED => next == BridgeStage.CHAR_ENUM_REQUESTED,
            BridgeStage.CHAR_ENUM_REQUESTED => next == BridgeStage.CHAR_ENUM_REQUESTED || next == BridgeStage.CHAR_ENUM_RECEIVED,
            BridgeStage.CHAR_ENUM_RECEIVED => next == BridgeStage.CHAR_ENUM_REQUESTED,
            _ => false
        };
    }

    private void MarkTemporalInvariantLocked(string name, bool passed, string expected, string actual)
    {
        _temporalInvariants.Add(
            new TemporalInvariantResult(
                Name: name,
                Passed: passed,
                Expected: expected,
                Actual: actual,
                TimestampUtc: DateTimeOffset.UtcNow.ToString("O")));
    }

    private void TryCaptureFirstDivergenceFromDiffPath(string diffPath)
    {
        if (string.IsNullOrWhiteSpace(diffPath) || !File.Exists(diffPath))
        {
            return;
        }

        try
        {
            foreach (string line in File.ReadLines(diffPath, Encoding.UTF8))
            {
                if (!line.StartsWith("idx=", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!TryParseFirstDiffLine(line, out int offset, out string? expected, out string? actual))
                {
                    continue;
                }

                lock (_stageSync)
                {
                    _firstDivergence = new FirstDivergenceRecord(
                        Offset: offset,
                        Layer: _activeLayer ?? "Payload",
                        ParityAxis: _parityAxis ?? "layout parity",
                        ExpectedBytes: expected,
                        ActualBytes: actual,
                        SourcePath: diffPath,
                        TimestampUtc: DateTimeOffset.UtcNow.ToString("O"));
                }

                return;
            }
        }
        catch (IOException)
        {
            // Best-effort evidence extraction only.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort evidence extraction only.
        }
    }

    private static bool TryParseFirstDiffLine(string line, out int offset, out string? expected, out string? actual)
    {
        offset = -1;
        expected = null;
        actual = null;

        // Format: idx=0: expected=01 actual=00
        int idxEq = line.IndexOf('=');
        int idxColon = line.IndexOf(':');
        if (idxEq < 0 || idxColon < 0 || idxColon <= idxEq + 1)
        {
            return false;
        }

        string offsetText = line.Substring(idxEq + 1, idxColon - idxEq - 1).Trim();
        if (!int.TryParse(offsetText, NumberStyles.Integer, CultureInfo.InvariantCulture, out offset))
        {
            return false;
        }

        string tail = line.Substring(idxColon + 1);
        string[] parts = tail.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (string part in parts)
        {
            if (part.StartsWith("expected=", StringComparison.OrdinalIgnoreCase))
            {
                expected = part.Substring("expected=".Length).Trim();
                continue;
            }

            if (part.StartsWith("actual=", StringComparison.OrdinalIgnoreCase))
            {
                actual = part.Substring("actual=".Length).Trim();
            }
        }

        return true;
    }

}
