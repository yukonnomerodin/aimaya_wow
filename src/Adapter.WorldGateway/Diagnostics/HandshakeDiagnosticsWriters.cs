using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Adapter.WorldGateway;

internal static class HandshakeDiagnosticsWriters
{
    public static ProofPackArtifacts WriteEnterEncryptedProofPack(
        uint connectionId,
        WorldProxyOptions options,
        EnterEncryptedModeProof proof,
        int accountId,
        string runlogsDir,
        string projectRoot)
    {
        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffZ");
        string hexPath = Path.Combine(runlogsDir, $"enter_encrypted_mode.sent.{stamp}.hex");
        string jsonPath = Path.Combine(runlogsDir, $"enter_encrypted_mode.sent.{stamp}.json");
        string diffPath = Path.Combine(runlogsDir, $"enter_encrypted_mode.diff.{stamp}.txt");

        File.WriteAllText(hexPath, proof.PayloadHex + Environment.NewLine, Encoding.ASCII);

        var metadata = new
        {
            connection_id = connectionId,
            account_id = accountId,
            timestamp_utc = proof.TimestampUtc,
            retail_opcode = $"0x{proof.RetailOpcode:X8}",
            region_group = proof.RegionGroup,
            include_region_group = proof.IncludeRegionGroup,
            enabled = proof.Enabled,
            enabled_as_byte = proof.EnabledAsByte,
            signature_first = proof.SignatureFirst,
            prefer_bnet_key_data = proof.PreferBnetKeyData,
            key_source = proof.KeySource,
            wire_format = proof.WireFormat,
            session_key_sha256 = proof.SessionKeySha256,
            bnet_key_data_sha256 = proof.BnetKeyDataSha256,
            bnet_key_derivation_error = proof.BnetKeyDerivationError,
            retail_world_encrypt_key_sha256 = proof.RetailWorldEncryptKeySha256,
            retail_world_encrypt_key_hex = proof.RetailWorldEncryptKeyHex,
            local_challenge_hex = proof.LocalChallengeHex,
            server_challenge_hex = proof.ServerChallengeHex,
            to_sign_hex = proof.ToSignHex,
            signature_hex = proof.SignatureHex,
            payload_hex = proof.PayloadHex,
            payload_bytes = proof.PayloadBytes
        };

        File.WriteAllText(
            jsonPath,
            JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);

        string diffSummary = BuildEnterEncryptedFixtureDiffSummary(options, proof, runlogsDir, projectRoot);
        File.WriteAllText(diffPath, diffSummary, Encoding.UTF8);

        return new ProofPackArtifacts(hexPath, jsonPath, diffPath);
    }

    public static EnterEncryptedPayloadParityResult EvaluateEnterEncryptedPayloadParity(
        WorldProxyOptions options,
        ReadOnlySpan<byte> actualPayload,
        string runlogsDir,
        string projectRoot)
    {
        string fixturePath = ResolveEnterEncryptedParityFixturePath(options, runlogsDir, projectRoot);
        if (string.IsNullOrWhiteSpace(fixturePath))
        {
            return new EnterEncryptedPayloadParityResult(
                FixtureFound: false,
                PayloadMatch: false,
                FixturePath: "<auto>",
                ExpectedLength: 0,
                ActualLength: actualPayload.Length,
                DiffCount: actualPayload.Length,
                FirstDiffIndex: null,
                FirstExpectedByte: null,
                FirstActualByte: null,
                SignatureBytesIgnored: false,
                SignatureOffset: null,
                SignatureBytes: 0,
                Error: "Golden fixture not found (auto-resolution failed).");
        }

        if (!TryLoadEnterEncryptedPayloadFromFixture(fixturePath, out byte[] expectedPayload, out string? loadError))
        {
            return new EnterEncryptedPayloadParityResult(
                FixtureFound: false,
                PayloadMatch: false,
                FixturePath: fixturePath,
                ExpectedLength: 0,
                ActualLength: actualPayload.Length,
                DiffCount: actualPayload.Length,
                FirstDiffIndex: null,
                FirstExpectedByte: null,
                FirstActualByte: null,
                SignatureBytesIgnored: false,
                SignatureOffset: null,
                SignatureBytes: 0,
                Error: loadError ?? "Unable to load fixture payload.");
        }

        bool signatureBytesIgnored = false;
        int signatureOffset = 0;
        int signatureBytes = 0;
        bool runtimeSignatureMode =
            !options.EnterEncryptedModeUseGoldenPayload ||
            options.EnterEncryptedModeGoldenPatchRuntimeSignature;
        if (runtimeSignatureMode &&
            TryGetEnterEncryptedSignatureWindow(
                expectedPayload.Length,
                options.EnterEncryptedModeIncludeRegionGroup,
                options.EnterEncryptedModeSignatureFirst,
                out int ignoreOffset,
                out int ignoreLength) &&
            ignoreOffset + ignoreLength <= actualPayload.Length)
        {
            signatureBytesIgnored = true;
            signatureOffset = ignoreOffset;
            signatureBytes = ignoreLength;
        }

        int min = Math.Min(expectedPayload.Length, actualPayload.Length);
        int diffCount = 0;
        int? firstDiffIndex = null;
        byte? firstExpected = null;
        byte? firstActual = null;
        for (int i = 0; i < min; i++)
        {
            if (signatureBytesIgnored && IsIndexInsideRange(i, signatureOffset, signatureBytes))
            {
                continue;
            }

            if (expectedPayload[i] == actualPayload[i])
            {
                continue;
            }

            diffCount++;
            if (firstDiffIndex is null)
            {
                firstDiffIndex = i;
                firstExpected = expectedPayload[i];
                firstActual = actualPayload[i];
            }
        }

        if (expectedPayload.Length != actualPayload.Length)
        {
            if (expectedPayload.Length > actualPayload.Length)
            {
                for (int i = actualPayload.Length; i < expectedPayload.Length; i++)
                {
                    if (signatureBytesIgnored && IsIndexInsideRange(i, signatureOffset, signatureBytes))
                    {
                        continue;
                    }

                    diffCount++;
                    if (firstDiffIndex is null)
                    {
                        firstDiffIndex = i;
                        firstExpected = expectedPayload[i];
                        firstActual = null;
                    }
                }
            }
            else
            {
                for (int i = expectedPayload.Length; i < actualPayload.Length; i++)
                {
                    if (signatureBytesIgnored && IsIndexInsideRange(i, signatureOffset, signatureBytes))
                    {
                        continue;
                    }

                    diffCount++;
                    if (firstDiffIndex is null)
                    {
                        firstDiffIndex = i;
                        firstExpected = null;
                        firstActual = actualPayload[i];
                    }
                }
            }
        }

        bool payloadMatch = diffCount == 0;
        return new EnterEncryptedPayloadParityResult(
            FixtureFound: true,
            PayloadMatch: payloadMatch,
            FixturePath: fixturePath,
            ExpectedLength: expectedPayload.Length,
            ActualLength: actualPayload.Length,
            DiffCount: diffCount,
            FirstDiffIndex: firstDiffIndex,
            FirstExpectedByte: firstExpected,
            FirstActualByte: firstActual,
            SignatureBytesIgnored: signatureBytesIgnored,
            SignatureOffset: signatureBytesIgnored ? signatureOffset : null,
            SignatureBytes: signatureBytesIgnored ? signatureBytes : 0,
            Error: null);
    }

    public static DeferredFrameParityResult EvaluateFirstDeferredFrameParity(
        string? fixturePathOption,
        ReadOnlySpan<byte> actualFrame,
        string projectRoot)
    {
        if (string.IsNullOrWhiteSpace(fixturePathOption))
        {
            return new DeferredFrameParityResult(
                Status: "fixture_not_configured",
                FixturePath: null,
                DiffOffset: null,
                ExpectedBytes: null,
                ActualBytes: null);
        }

        string fixturePath = fixturePathOption;
        if (!Path.IsPathRooted(fixturePath))
        {
            fixturePath = Path.Combine(projectRoot, fixturePath);
        }

        if (!HexPayloadLoader.TryLoadHexPayloadFromFile(
                fixturePath,
                projectRoot,
                out byte[] expectedFrame,
                out string? loadError,
                out string? resolvedPath))
        {
            return new DeferredFrameParityResult(
                Status: "fixture_load_error",
                FixturePath: resolvedPath ?? fixturePath,
                DiffOffset: null,
                ExpectedBytes: loadError,
                ActualBytes: null);
        }

        int compareLength = Math.Min(expectedFrame.Length, actualFrame.Length);
        int? diffOffset = null;
        for (int idx = 0; idx < compareLength; idx++)
        {
            if (expectedFrame[idx] != actualFrame[idx])
            {
                diffOffset = idx;
                break;
            }
        }

        if (!diffOffset.HasValue && expectedFrame.Length != actualFrame.Length)
        {
            diffOffset = compareLength;
        }

        if (!diffOffset.HasValue)
        {
            return new DeferredFrameParityResult(
                Status: "match",
                FixturePath: resolvedPath ?? fixturePath,
                DiffOffset: null,
                ExpectedBytes: null,
                ActualBytes: null);
        }

        int offset = diffOffset.Value;
        return new DeferredFrameParityResult(
            Status: "mismatch",
            FixturePath: resolvedPath ?? fixturePath,
            DiffOffset: offset,
            ExpectedBytes: BuildHexWindow(expectedFrame, offset),
            ActualBytes: BuildHexWindow(actualFrame, offset));
    }

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
            service_boundary_contract_version = report.ServiceBoundaryContractVersion,
            relay_failure_recovery_policy = report.RelayFailureRecoveryPolicy,
            relay_failure_drain_timeout_ms = report.RelayFailureDrainTimeoutMs,
            db_auth_bridge_timeout_ms = report.DbAuthBridgeTimeoutMs,
            handshake_diagnostics_dispatch_mode = report.HandshakeDiagnosticsDispatchMode,
            handshake_diagnostics_queue_enqueue_attempt_total = report.HandshakeDiagnosticsQueueEnqueueAttemptTotal,
            handshake_diagnostics_queue_enqueued_total = report.HandshakeDiagnosticsQueueEnqueuedTotal,
            handshake_diagnostics_queue_saturation_fallback_total = report.HandshakeDiagnosticsQueueSaturationFallbackTotal,
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

    private static string BuildEnterEncryptedFixtureDiffSummary(
        WorldProxyOptions options,
        EnterEncryptedModeProof proof,
        string runlogsDir,
        string projectRoot)
    {
        var sb = new StringBuilder(512);
        sb.AppendLine($"retail_opcode=0x{proof.RetailOpcode:X8}");
        sb.AppendLine($"include_region_group={proof.IncludeRegionGroup}");
        sb.AppendLine($"enabled_as_byte={proof.EnabledAsByte}");
        sb.AppendLine($"wire_format={proof.WireFormat}");
        sb.AppendLine($"signature_first={proof.SignatureFirst}");

        try
        {
            byte[] actualPayload = Convert.FromHexString(proof.PayloadHex);
            EnterEncryptedPayloadParityResult parity = EvaluateEnterEncryptedPayloadParity(options, actualPayload, runlogsDir, projectRoot);
            if (parity.FixtureFound)
            {
                sb.AppendLine($"fixture_path={parity.FixturePath}");
                sb.AppendLine("status=ok");
                sb.AppendLine($"expected_len={parity.ExpectedLength}");
                sb.AppendLine($"actual_len={parity.ActualLength}");
                sb.AppendLine($"byte_diff_count={parity.DiffCount}");
                if (parity.SignatureBytesIgnored &&
                    parity.SignatureOffset is int signatureOffset &&
                    parity.SignatureBytes > 0)
                {
                    sb.AppendLine("signature_range_ignored=true");
                    sb.AppendLine($"signature_offset={signatureOffset}");
                    sb.AppendLine($"signature_bytes={parity.SignatureBytes}");
                }

                if (parity.FirstDiffIndex is int firstDiff &&
                    parity.FirstExpectedByte is byte expectedByte &&
                    parity.FirstActualByte is byte actualByte)
                {
                    sb.AppendLine("first_differences:");
                    sb.AppendLine($"idx={firstDiff}: expected={expectedByte:X2} actual={actualByte:X2}");
                }

                return sb.ToString();
            }

            sb.AppendLine($"fixture_path={parity.FixturePath}");
            sb.AppendLine($"status={(options.EnterEncryptedModeParityGateEnabled ? "fixture_missing_gate_skipped" : "fixture_missing")}");
            if (!string.IsNullOrWhiteSpace(parity.Error))
            {
                sb.AppendLine($"error={parity.Error}");
            }
        }
        catch (FormatException ex)
        {
            sb.AppendLine("status=actual_payload_invalid_hex");
            sb.AppendLine($"error={ex.Message}");
            return sb.ToString();
        }

        string fixturePath = ResolveFixturePath(options, projectRoot);
        sb.AppendLine($"synthetic_fixture_path={fixturePath}");
        if (!File.Exists(fixturePath))
        {
            return sb.ToString();
        }

        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(fixturePath, Encoding.UTF8));
        if (!doc.RootElement.TryGetProperty("payloads", out JsonElement payloads))
        {
            return sb.ToString();
        }

        string payloadKey = proof.SignatureFirst ? "signature_region_bit" : "region_signature_bit";
        if (!payloads.TryGetProperty(payloadKey, out JsonElement expectedPayloadElement))
        {
            return sb.ToString();
        }

        string expectedHex = expectedPayloadElement.GetString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(expectedHex))
        {
            return sb.ToString();
        }

        byte[] expected = Convert.FromHexString(expectedHex);
        byte[] actual = Convert.FromHexString(proof.PayloadHex);
        int min = Math.Min(expected.Length, actual.Length);
        int diff = 0;
        for (int i = 0; i < min; i++)
        {
            if (expected[i] != actual[i])
            {
                diff++;
            }
        }

        int tailDiff = Math.Abs(expected.Length - actual.Length);
        sb.AppendLine($"synthetic_expected_len={expected.Length}");
        sb.AppendLine($"synthetic_actual_len={actual.Length}");
        sb.AppendLine($"synthetic_byte_diff_count={diff + tailDiff}");
        return sb.ToString();
    }

    private static bool TryGetEnterEncryptedSignatureWindow(
        int payloadLength,
        bool includeRegionGroup,
        bool signatureFirst,
        out int signatureOffset,
        out int signatureLength)
    {
        signatureOffset = 0;
        signatureLength = 64;

        if (payloadLength < 65)
        {
            return false;
        }

        signatureOffset = includeRegionGroup
            ? (signatureFirst ? 0 : 4)
            : 0;

        return signatureOffset >= 0 &&
            signatureLength > 0 &&
            signatureOffset + signatureLength <= payloadLength;
    }

    private static bool IsIndexInsideRange(int index, int rangeStart, int rangeLength)
    {
        if (rangeLength <= 0)
        {
            return false;
        }

        return index >= rangeStart && index < rangeStart + rangeLength;
    }

    private static string ResolveEnterEncryptedParityFixturePath(
        WorldProxyOptions options,
        string runlogsDir,
        string projectRoot)
    {
        if (!string.IsNullOrWhiteSpace(options.EnterEncryptedModeParityFixturePath))
        {
            string explicitPath = options.EnterEncryptedModeParityFixturePath;
            if (!Path.IsPathRooted(explicitPath))
            {
                explicitPath = Path.Combine(projectRoot, explicitPath);
            }

            return explicitPath;
        }

        string? latestHex = TryFindLatestByPattern(runlogsDir, "enter_encrypted_mode.golden*.hex");
        if (!string.IsNullOrWhiteSpace(latestHex))
        {
            return latestHex;
        }

        string? latestJson = TryFindLatestByPattern(runlogsDir, "enter_encrypted_mode.golden*.json");
        if (!string.IsNullOrWhiteSpace(latestJson))
        {
            return latestJson;
        }

        return string.Empty;
    }

    private static string? TryFindLatestByPattern(string directoryPath, string searchPattern)
    {
        if (!Directory.Exists(directoryPath))
        {
            return null;
        }

        string[] files = Directory.GetFiles(directoryPath, searchPattern, SearchOption.TopDirectoryOnly);
        if (files.Length == 0)
        {
            return null;
        }

        string? latest = null;
        DateTime latestWrite = DateTime.MinValue;
        for (int idx = 0; idx < files.Length; idx++)
        {
            DateTime writeTime = File.GetLastWriteTimeUtc(files[idx]);
            if (writeTime > latestWrite)
            {
                latestWrite = writeTime;
                latest = files[idx];
            }
        }

        return latest;
    }

    private static bool TryLoadEnterEncryptedPayloadFromFixture(string fixturePath, out byte[] payload, out string? error)
    {
        payload = Array.Empty<byte>();
        error = null;

        if (string.IsNullOrWhiteSpace(fixturePath))
        {
            error = "Fixture path is empty.";
            return false;
        }

        if (!File.Exists(fixturePath))
        {
            error = $"Fixture path does not exist: {fixturePath}";
            return false;
        }

        string extension = Path.GetExtension(fixturePath);
        try
        {
            if (string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase))
            {
                using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(fixturePath, Encoding.UTF8));
                if (!doc.RootElement.TryGetProperty("payload_hex", out JsonElement payloadElement))
                {
                    error = $"payload_hex is missing in fixture: {fixturePath}";
                    return false;
                }

                string payloadHex = payloadElement.GetString() ?? string.Empty;
                return HexPayloadLoader.TryParseHexPayload(payloadHex, fixturePath, out payload, out error);
            }

            string rawHex = File.ReadAllText(fixturePath, Encoding.ASCII);
            return HexPayloadLoader.TryParseHexPayload(rawHex, fixturePath, out payload, out error);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string ResolveFixturePath(WorldProxyOptions options, string projectRoot)
    {
        string preferred = Path.Combine(projectRoot, options.ProofPackRootPath, "fixtures", "enter_encrypted_mode.synthetic.v1.json");
        if (File.Exists(preferred))
        {
            return preferred;
        }

        return Path.Combine(projectRoot, "docs", "handshake", "fixtures", "enter_encrypted_mode.synthetic.v1.json");
    }


    private static string BuildHexWindow(ReadOnlySpan<byte> bytes, int startOffset)
    {
        if (bytes.IsEmpty)
        {
            return "<empty>";
        }

        int start = Math.Max(0, Math.Min(startOffset, bytes.Length - 1));
        int length = Math.Min(16, bytes.Length - start);
        return Convert.ToHexString(bytes.Slice(start, length));
    }
}
