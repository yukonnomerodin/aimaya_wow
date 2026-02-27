using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Adapter.WorldGateway;

internal static class HandshakeDiagnosticsWriters
{
    public static AuthChallengeProofArtifacts WriteAuthChallengeProofPack(
        uint connectionId,
        string runlogsDir,
        RetailAuthChallengeProof proof)
    {
        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffZ");
        string hexPath = Path.Combine(runlogsDir, $"auth_challenge.sent.{stamp}.hex");
        string jsonPath = Path.Combine(runlogsDir, $"auth_challenge.sent.{stamp}.json");

        File.WriteAllText(hexPath, proof.RetailPayloadHex + Environment.NewLine, Encoding.ASCII);

        var metadata = new
        {
            connection_id = connectionId,
            timestamp_utc = proof.TimestampUtc,
            retail_opcode = $"0x{proof.RetailOpcode:X8}",
            acore_dos_challenge = proof.AcoreDosChallenge,
            acore_auth_seed = $"0x{proof.AcoreAuthSeed:X8}",
            acore_new_seed_hex = proof.AcoreNewSeedHex,
            dos_block_source = proof.DosBlockSource,
            dos_block_hex = proof.DosBlockHex,
            challenge_block_hex = proof.ChallengeBlockHex,
            retail_payload_hex = proof.RetailPayloadHex,
            retail_payload_bytes = proof.RetailPayloadBytes
        };

        File.WriteAllText(
            jsonPath,
            JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);

        return new AuthChallengeProofArtifacts(hexPath, jsonPath);
    }

    public static string WriteHandshakeLabReport(HandshakeLabReport report, string runlogsDir)
    {
        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffZ");
        string reportPath = Path.Combine(runlogsDir, $"handshake_lab.{stamp}.json");

        var payload = new
        {
            timestamp_utc = report.TimestampUtc,
            scenario_id = report.ScenarioId,
            pass_threshold = report.PassThreshold,
            ack_policy = report.AckPolicy,
            deterministic_replay_enabled = report.DeterministicReplayEnabled,
            hypothesis_id = report.HypothesisId,
            single_changed_variable = report.SingleChangedVariable,
            expected_observable = report.ExpectedObservable,
            next_isolation_variable = report.NextIsolationVariable,
            failure_class_target = report.FailureClassTarget,
            failure_class = report.FailureClass,
            layer = report.ActiveLayer,
            parity_axis = report.ParityAxis,
            connection_id = report.ConnectionId,
            ack_observed = report.AckObserved,
            ack_confirmed_elapsed_ms = report.AckConfirmedElapsedMs,
            disconnect_reason = report.DisconnectReason,
            disconnect_elapsed_ms = report.DisconnectElapsedMs,
            timeout_pending_bytes = report.TimeoutPendingBytes,
            timeout_pending_retail = report.TimeoutPendingRetail,
            enter_encrypted_payload_hex_path = report.EnterEncryptedPayloadHexPath,
            enter_encrypted_payload_metadata_path = report.EnterEncryptedPayloadMetadataPath,
            enter_encrypted_payload_diff_path = report.EnterEncryptedPayloadDiffPath,
            signature_first = report.SignatureFirst,
            region_group = report.RegionGroup,
            include_region_group = report.IncludeRegionGroup,
            enter_encrypted_enabled = report.EnterEncryptedEnabled,
            enter_encrypted_enabled_as_byte = report.EnterEncryptedEnabledAsByte,
            enter_encrypted_opcode = report.EnterEncryptedOpcode,
            enter_encrypted_prefer_bnet_key_data = report.EnterEncryptedPreferBnetKeyData,
            ack_timeout_ms = report.AckTimeoutMs,
            awaiting_retail_opcodes = report.AwaitingRetailOpcodes,
            bytes_client_to_world = report.BytesClientToWorld,
            bytes_world_to_client = report.BytesWorldToClient,
            connection_opened_at_utc = report.ConnectionOpenedAtUtc,
            connection_closed_at_utc = report.ConnectionClosedAtUtc,
            connection_duration_ms = report.ConnectionDurationMs,
            current_stage = report.CurrentStage,
            char_enum_requested = report.CharEnumRequested,
            char_enum_received = report.CharEnumReceived,
            boundary = report.Boundary,
            deferred_first = report.DeferredFirst,
            deferred_first_server_counter = report.DeferredFirstServerCounter,
            deferred_first_plain_sha256 = report.DeferredFirstPlainSha256,
            deferred_first_protected_sha256 = report.DeferredFirstProtectedSha256,
            deferred_first_protected_tag_hex = report.DeferredFirstProtectedTagHex,
            deferred_first_parity_status = report.DeferredFirstParityStatus,
            deferred_first_parity_diff_offset = report.DeferredFirstParityDiffOffset,
            deferred_first_parity_expected_bytes = report.DeferredFirstParityExpectedBytes,
            deferred_first_parity_actual_bytes = report.DeferredFirstParityActualBytes,
            deferred_first_parity_fixture_path = report.DeferredFirstParityFixturePath,
            deferred_flush_path = report.DeferredFlushPath,
            post_ack_non_ack_trigger_opcode = report.PostAckNonAckTriggerOpcode,
            post_ack_non_ack_trigger_wait_ms = report.PostAckNonAckTriggerWaitMs,
            run_valid = report.RunValid,
            run_valid_reason = report.RunValidReason,
            first_divergence_offset = report.FirstDivergenceOffset,
            first_divergence_expected_bytes = report.FirstDivergenceExpectedBytes,
            first_divergence_actual_bytes = report.FirstDivergenceActualBytes,
            first_divergence_source_path = report.FirstDivergenceSourcePath,
            stage_transitions = report.StageTransitions,
            temporal_invariants = report.TemporalInvariants,
            baseline = report.Baseline
        };

        File.WriteAllText(
            reportPath,
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);
        return reportPath;
    }

    public static void AppendNegativeEvidenceMatrixRow(
        string reportPath,
        HandshakeLabReport report,
        string proofRoot)
    {
        if (string.Equals(report.FailureClass, "none", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string matrixDir = Path.Combine(proofRoot, "matrix");
        Directory.CreateDirectory(matrixDir);
        string matrixPath = Path.Combine(matrixDir, "negative_evidence.csv");

        if (!File.Exists(matrixPath))
        {
            const string header =
                "hypothesis_id,layer,parity_axis,single_changed_variable,expected_observable,actual_observable,failure_class,decision,next_isolation_variable";
            File.WriteAllText(matrixPath, header + Environment.NewLine, Encoding.UTF8);
        }

        string hypothesisId = string.IsNullOrWhiteSpace(report.HypothesisId)
            ? $"{report.ScenarioId}:{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffZ}"
            : report.HypothesisId;
        string expectedObservable = string.IsNullOrWhiteSpace(report.ExpectedObservable)
            ? $"Reach CHAR_ENUM_RECEIVED without reason=3/24/no ACK (target={report.FailureClassTarget})"
            : report.ExpectedObservable;
        string actualObservable =
            $"stage={report.CurrentStage}; char_enum_received={report.CharEnumReceived}; ack_observed={report.AckObserved}; disconnect_reason={report.DisconnectReason?.ToString(CultureInfo.InvariantCulture) ?? "<none>"}; boundary={report.Boundary}; deferred_first={report.DeferredFirst}; deferred_flush_path={report.DeferredFlushPath}; deferred_first_server_counter={report.DeferredFirstServerCounter?.ToString(CultureInfo.InvariantCulture) ?? "<none>"}; deferred_first_tag={report.DeferredFirstProtectedTagHex ?? "<none>"}; deferred_first_parity_status={report.DeferredFirstParityStatus ?? "<none>"}; post_ack_trigger_opcode={report.PostAckNonAckTriggerOpcode?.ToString("X8", CultureInfo.InvariantCulture) ?? "<none>"}; run_valid={report.RunValid}; first_divergence_offset={report.FirstDivergenceOffset?.ToString(CultureInfo.InvariantCulture) ?? "<none>"}; artifact={reportPath}";
        string decision = string.Equals(report.FailureClass, "inconclusive", StringComparison.OrdinalIgnoreCase)
            ? "inconclusive"
            : "rejected";
        string nextIsolationVariable = string.IsNullOrWhiteSpace(report.NextIsolationVariable)
            ? ResolveNextIsolationVariable(report.FailureClass)
            : report.NextIsolationVariable;
        string singleChangedVariable = string.IsNullOrWhiteSpace(report.SingleChangedVariable)
            ? "runtime_change_untracked"
            : report.SingleChangedVariable;

        string[] columns =
        [
            hypothesisId,
            report.ActiveLayer,
            report.ParityAxis,
            singleChangedVariable,
            expectedObservable,
            actualObservable,
            report.FailureClass,
            decision,
            nextIsolationVariable
        ];

        string line = string.Join(",", columns.Select(EscapeCsv));
        File.AppendAllText(matrixPath, line + Environment.NewLine, Encoding.UTF8);
    }

    private static string ResolveNextIsolationVariable(string failureClass)
    {
        if (string.Equals(failureClass, "reason=24", StringComparison.OrdinalIgnoreCase))
        {
            return "opcode_map_tuple(direction,state,build)";
        }

        if (string.Equals(failureClass, "reason=3", StringComparison.OrdinalIgnoreCase))
        {
            return "state_gate_or_db_parity";
        }

        if (string.Equals(failureClass, "no ACK", StringComparison.OrdinalIgnoreCase))
        {
            return "framing_header_or_crypto_boundary";
        }

        if (string.Equals(failureClass, "db_mismatch", StringComparison.OrdinalIgnoreCase))
        {
            return "account_session_build_flags";
        }

        return "first_divergence_layer_followup";
    }

    private static string EscapeCsv(string value)
    {
        if (value.IndexOfAny([',', '"', '\r', '\n']) < 0)
        {
            return value;
        }

        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
