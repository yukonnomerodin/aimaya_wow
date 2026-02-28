using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipelines;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct AckGateDeferredFlushResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private async ValueTask<AckGateDeferredFlushResult> TryHandleAckGateAndDeferredFlushAsync(
        uint connectionId,
        string direction,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;

if (direction == "world->client" && bridgeState.IsAwaitingEnterEncryptedAck)
        {
            bool fallbackFlushEnabled =
                _bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck &&
                _options.BootstrapFlushTriggerFallbackTimeoutMs > 0;
            int ackWaitTimeoutMs = _options.EnterEncryptedModeAckTimeoutMs;
            if (fallbackFlushEnabled)
            {
                ackWaitTimeoutMs = Math.Min(ackWaitTimeoutMs, _options.BootstrapFlushTriggerFallbackTimeoutMs);
            }

            TimeSpan timeout = TimeSpan.FromMilliseconds(ackWaitTimeoutMs);
            long waitStartMs = Environment.TickCount64;
            bool acked = bridgeState.WaitForEnterEncryptedAck(timeout);
            long elapsedMs = Environment.TickCount64 - waitStartMs;
            bool fallbackFlushWithoutAck = false;
            string ackExpected = fallbackFlushEnabled
                ? $"ACK within {ackWaitTimeoutMs}ms (fallback window)"
                : $"ACK within {_options.EnterEncryptedModeAckTimeoutMs}ms";

            if (!acked)
            {
                bridgeState.TryPeekDeferredPostAuthInfo(out int pendingBytes, out string pendingRetail);
                bridgeState.MarkEnterEncryptedAckTimeout(pendingBytes, pendingRetail);
                if (fallbackFlushEnabled)
                {
                    fallbackFlushWithoutAck = true;
                    bridgeState.MarkTemporalInvariant(
                        name: "enter_encrypted_ack_within_timeout",
                        passed: false,
                        expected: ackExpected,
                        actual: $"no ACK in {elapsedMs}ms; continuing with fallback bootstrap flush (pending bytes={pendingBytes})");
                    bridgeState.MarkTemporalInvariant(
                        name: "bootstrap_flush_trigger_fallback_timeout",
                        passed: true,
                        expected: "flush deferred bootstrap when post-ACK trigger is absent within fallback timeout",
                        actual: $"fallback timeout {ackWaitTimeoutMs}ms reached; pending retail={pendingRetail}");
                    _logger.LogWarning(
                        "[WorldProxy][HANDSHAKE] ACK not observed within fallback window. ConnectionId={ConnectionId}, FallbackTimeoutMs={TimeoutMs}, ElapsedMs={ElapsedMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}. Proceeding with deferred bootstrap flush without ACK.",
                        connectionId,
                        ackWaitTimeoutMs,
                        elapsedMs,
                        pendingBytes,
                        pendingRetail);
                }
                else
                {
                    bridgeState.MarkTemporalInvariant(
                        name: "enter_encrypted_ack_within_timeout",
                        passed: false,
                        expected: ackExpected,
                        actual: $"timeout after {elapsedMs}ms (pending bytes={pendingBytes})");
                    _logger.LogWarning(
                        "[WorldProxy][HANDSHAKE] Timeout waiting for CMSG_ENTER_ENCRYPTED_MODE_ACK. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, ElapsedMs={ElapsedMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}",
                        connectionId,
                        _options.EnterEncryptedModeAckTimeoutMs,
                        elapsedMs,
                        pendingBytes,
                        pendingRetail);

                    bridgeState.ResetEnterEncryptedAwait();
                    return new AckGateDeferredFlushResult(ShouldTerminateConnection: true, ShouldBreakRelay: false, BytesWritten: bytesWritten);
                }
            }

            if (!fallbackFlushWithoutAck)
            {
                _logger.LogInformation(
                    "[WorldProxy][HANDSHAKE] CMSG_ENTER_ENCRYPTED_MODE_ACK confirmed. ConnectionId={ConnectionId}, ElapsedMs={ElapsedMs}",
                    connectionId,
                    elapsedMs);
                bridgeState.MarkTemporalInvariant(
                    name: "enter_encrypted_ack_within_timeout",
                    passed: true,
                    expected: ackExpected,
                    actual: $"ACK confirmed in {elapsedMs}ms");
                bridgeState.MarkEnterEncryptedAckConfirmed(elapsedMs);
                if (_options.EnableRetailWorldPacketCryptOnAck)
                {
                    if (!bridgeState.TryEnableRetailWorldCrypt(out string? enableError))
                    {
                        _logger.LogWarning(
                            "[WorldProxy][CRYPT] Failed to enable Retail world packet crypt after ACK confirmation. ConnectionId={ConnectionId}, Error={Error}",
                            connectionId,
                            enableError ?? "<unknown>");
                    }
                }
                else
                {
                    _logger.LogInformation(
                        "[WorldProxy][CRYPT] Retail world packet crypt-on-ACK disabled by config after ACK confirmation. ConnectionId={ConnectionId}",
                        connectionId);
                }
            }
            else
            {
                _logger.LogInformation(
                    "[WorldProxy][HANDSHAKE] Continuing with deferred bootstrap flush without ACK confirmation due to configured fallback timeout. ConnectionId={ConnectionId}",
                    connectionId);
            }

            bridgeState.ResetEnterEncryptedAwait();

            bool shouldFlushDeferredNow = true;
            string deferredFlushPath = fallbackFlushWithoutAck ? "fallback_without_ack" : "ack_gate";
            if (!fallbackFlushWithoutAck &&
                _bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck)
            {
                int triggerTimeoutMs = _options.EnterEncryptedModeAckTimeoutMs;
                if (_options.BootstrapFlushTriggerFallbackTimeoutMs > 0)
                {
                    triggerTimeoutMs = Math.Min(triggerTimeoutMs, _options.BootstrapFlushTriggerFallbackTimeoutMs);
                }

                bridgeState.BeginPostAckNonAckBootstrapTriggerAwait();
                _logger.LogInformation(
                    "[WorldProxy][HANDSHAKE] Deferred post-auth bootstrap flush is waiting for first post-ACK non-ACK client frame. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}",
                    connectionId,
                    triggerTimeoutMs);

                TimeSpan triggerTimeout = TimeSpan.FromMilliseconds(triggerTimeoutMs);
                long triggerWaitStartMs = Environment.TickCount64;
                bool triggerObserved = bridgeState.WaitForPostAckNonAckBootstrapTrigger(triggerTimeout);
                long triggerElapsedMs = Environment.TickCount64 - triggerWaitStartMs;
                bridgeState.EndPostAckNonAckBootstrapTriggerAwait();

                if (triggerObserved &&
                    bridgeState.TryGetPostAckNonAckBootstrapTriggerOpcode(out uint triggerOpcode))
                {
                    deferredFlushPath = "post_ack_non_ack_trigger";
                    bridgeState.MarkPostAckNonAckBootstrapTriggerWait(triggerElapsedMs);
                    bridgeState.MarkTemporalInvariant(
                        name: "bootstrap_flush_trigger_post_ack_non_ack",
                        passed: true,
                        expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                        actual: $"triggered by opcode=0x{triggerOpcode:X8} after {triggerElapsedMs}ms");
                    _logger.LogInformation(
                        "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger fired. ConnectionId={ConnectionId}, TriggerOpcode=0x{Opcode:X8}, WaitMs={WaitMs}",
                        connectionId,
                        triggerOpcode,
                        triggerElapsedMs);
                }
                else
                {
                    bridgeState.TryPeekDeferredPostAuthInfo(out int pendingBytes, out string pendingRetail);
                    bool fallbackFlushOnTriggerTimeout = _options.BootstrapFlushTriggerFallbackTimeoutMs > 0;
                    if (fallbackFlushOnTriggerTimeout)
                    {
                        shouldFlushDeferredNow = true;
                        deferredFlushPath = "post_ack_non_ack_fallback_timeout";
                        bridgeState.MarkTemporalInvariant(
                            name: "bootstrap_flush_trigger_post_ack_non_ack",
                            passed: false,
                            expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                            actual: $"timeout after {triggerElapsedMs}ms; fallback flush enabled (pending bytes={pendingBytes}, pending retail={pendingRetail})");
                        bridgeState.MarkTemporalInvariant(
                            name: "bootstrap_flush_trigger_post_ack_non_ack_fallback",
                            passed: true,
                            expected: "flush deferred bootstrap on trigger-timeout when fallback timeout is configured",
                            actual: $"fallback timeout {triggerTimeoutMs}ms reached; flushing pending retail={pendingRetail}");
                        _logger.LogWarning(
                            "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, WaitMs={WaitMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}. Proceeding with fallback flush.",
                            connectionId,
                            triggerTimeoutMs,
                            triggerElapsedMs,
                            pendingBytes,
                            pendingRetail);
                    }
                    else
                    {
                        shouldFlushDeferredNow = false;
                        deferredFlushPath = "post_ack_non_ack_timeout_no_flush";
                        bridgeState.MarkTemporalInvariant(
                            name: "bootstrap_flush_trigger_post_ack_non_ack",
                            passed: false,
                            expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                            actual: $"timeout after {triggerElapsedMs}ms (pending bytes={pendingBytes}, pending retail={pendingRetail})");
                        _logger.LogWarning(
                            "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, WaitMs={WaitMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}",
                            connectionId,
                            triggerTimeoutMs,
                            triggerElapsedMs,
                            pendingBytes,
                            pendingRetail);
                    }
                }
            }

            bridgeState.MarkDeferredFlushPath(deferredFlushPath);
            if (shouldFlushDeferredNow &&
                bridgeState.TryTakeDeferredPostAuthPayload(out byte[] deferredPayload, out string stagedOpcodes) &&
                deferredPayload.Length > 0)
            {
                if (_options.SuppressPostAuthBootstrapForProbe && !_options.ProbeBareAuthResponseOnly)
                {
                    bridgeState.MarkDeferredFlushPath("suppressed");
                    bridgeState.MarkTemporalInvariant(
                        name: "bootstrap_suppressed_for_probe",
                        passed: false,
                        expected: "bootstrap should flush in milestone scenario",
                        actual: "bootstrap suppressed by probe mode");
                    _logger.LogWarning(
                        "[WorldProxy][HANDSHAKE] Probe mode: suppressed deferred post-auth bootstrap after ACK gate. ConnectionId={ConnectionId}, SuppressedBytes={Bytes}, Retail={Retail}",
                        connectionId,
                        deferredPayload.Length,
                        stagedOpcodes);
                    bridgeState.TryTransitionStage(
                        BridgeStage.BOOTSTRAP_FLUSHED,
                        "Deferred post-auth bootstrap suppressed by probe mode after ACK gate.");

                    if (_options.ProbeExplicitBootstrapFlushMarker)
                    {
                        bridgeState.MarkTemporalInvariant(
                            name: "bootstrap_flush_marker_explicit",
                            passed: true,
                            expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                            actual: $"path=suppressed;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                            connectionId,
                            "suppressed",
                            deferredPayload.Length,
                            stagedOpcodes);
                    }
                }
                else if (!RetailFrameCodec.TrySplitRetailWorldFrames(deferredPayload, out List<RetailFrameChunk> deferredFrames, out string? splitError))
                {
                    bridgeState.MarkDeferredFlushPath("raw_payload_fallback");
                    _logger.LogWarning(
                        "[WorldProxy][HANDSHAKE] Failed to split deferred post-auth bootstrap into Retail frames. ConnectionId={ConnectionId}, Error={Error}, Bytes={Bytes}, Retail={Retail}",
                        connectionId,
                        splitError ?? "<unknown>",
                        deferredPayload.Length,
                        stagedOpcodes);

                    writer.Write(deferredPayload);
                    bytesWritten += deferredPayload.Length;

                    FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
                    {
                        return new AckGateDeferredFlushResult(ShouldTerminateConnection: false, ShouldBreakRelay: true, BytesWritten: bytesWritten);
                    }

                    bridgeState.TryTransitionStage(
                        BridgeStage.BOOTSTRAP_FLUSHED,
                        "Deferred post-auth bootstrap flushed after ACK gate (raw payload fallback).");

                    if (_options.ProbeExplicitBootstrapFlushMarker)
                    {
                        bridgeState.MarkTemporalInvariant(
                            name: "bootstrap_flush_marker_explicit",
                            passed: true,
                            expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                            actual: $"path=raw_payload_fallback;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                            connectionId,
                            "raw_payload_fallback",
                            deferredPayload.Length,
                            stagedOpcodes);
                    }
                }
                else
                {
                    _logger.LogInformation(
                        "[WorldProxy][HANDSHAKE] Flushing deferred post-auth bootstrap. ConnectionId={ConnectionId}, Frames={Frames}, Bytes={Bytes}, Retail={Retail}",
                        connectionId,
                        deferredFrames.Count,
                        deferredPayload.Length,
                        stagedOpcodes);

                    bridgeState.BeginDeferredBootstrapFlush(deferredFrames.Count);
                    bool deferredInterrupted = false;
                    for (int frameIndex = 0; frameIndex < deferredFrames.Count; frameIndex++)
                    {
                        RetailFrameChunk frame = deferredFrames[frameIndex];
                        bool shouldDropFrame = _probeDropDeferredOpcodes.Contains(frame.Opcode);
                        if (_options.ProbeBareAuthResponseOnly &&
                            frame.Opcode == WorldGatewayOpcodes.RetailSmsgAuthResponse)
                        {
                            // In bare AUTH_RESPONSE probe mode, always deliver AUTH_RESPONSE even if
                            // legacy probe drop list still includes it from previous experiments.
                            shouldDropFrame = false;
                        }

                        if (shouldDropFrame)
                        {
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Probe mode: dropped deferred frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, BodyLength={BodyLength}",
                                connectionId,
                                frameIndex + 1,
                                deferredFrames.Count,
                                frame.Opcode,
                                frame.BodyLength);
                            continue;
                        }

                        bool isPreludeFrame = frame.Opcode == WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude;
                        bool isAuthResponseFrame = frame.Opcode == _probeAuthResponseOpcode;
                        if (isAuthResponseFrame)
                        {
                            bool plainEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(frame.Frame, out string plainEnvelopeActual);
                            bridgeState.MarkTemporalInvariant(
                                name: "auth_response_plaintext_envelope_invariant",
                                passed: plainEnvelopeOk,
                                expected: "plaintext frame: size=opcode+payload, frame_bytes=16+size, size excludes 12-byte tag",
                                actual: plainEnvelopeActual);

                            if (!plainEnvelopeOk)
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][ENVELOPE] Plain AUTH_RESPONSE envelope invariant failed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Actual={Actual}",
                                    connectionId,
                                    frame.Opcode,
                                    plainEnvelopeActual);
                            }
                        }

                        if (!bridgeState.TryProtectRetailServerFrame(
                                frame.Frame,
                                out byte[] protectedFrame,
                                out ulong serverCounterUsed,
                                out string? protectError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][CRYPT] Failed to protect deferred Retail frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, Error={Error}",
                                connectionId,
                                frameIndex + 1,
                                deferredFrames.Count,
                                frame.Opcode,
                                protectError ?? "<unknown>");

                            return new AckGateDeferredFlushResult(ShouldTerminateConnection: true, ShouldBreakRelay: false, BytesWritten: bytesWritten);
                        }

                        string plainSha256 = Convert.ToHexString(SHA256.HashData(frame.Frame));
                        string protectedSha256 = Convert.ToHexString(SHA256.HashData(protectedFrame));
                        string protectedTagHex = Convert.ToHexString(protectedFrame.AsSpan(4, 12));
                        DeferredFrameParityResult deferredParity = new(
                            Status: "not_evaluated",
                            FixturePath: null,
                            DiffOffset: null,
                            ExpectedBytes: null,
                            ActualBytes: null);

                        if (isPreludeFrame)
                        {
                            bool protectedEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(protectedFrame, out string preludeEnvelopeActual);
                            uint protectedSize = protectedEnvelopeOk
                                ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(0, 4))
                                : 0u;
                            uint protectedOpcode = protectedEnvelopeOk
                                ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(16, 4))
                                : 0u;
                            bool sizePreserved = protectedEnvelopeOk &&
                                protectedSize == (uint)frame.BodyLength &&
                                protectedFrame.Length == frame.Frame.Length;
                            bool opcodeEncryptedWhenCryptActive = !bridgeState.IsRetailWorldCryptActive ||
                                protectedOpcode != frame.Opcode;
                            bool preludeInvariantPassed = sizePreserved && opcodeEncryptedWhenCryptActive;
                            bridgeState.MarkTemporalInvariant(
                                name: "prelude_encrypted_envelope_invariant",
                                passed: preludeInvariantPassed,
                                expected: "if world crypt is active, prelude opcode bytes must be encrypted while envelope size stays preserved",
                                actual: $"{preludeEnvelopeActual};world_crypt_active={bridgeState.IsRetailWorldCryptActive};plain_opcode=0x{frame.Opcode:X8};protected_opcode=0x{protectedOpcode:X8};size_preserved={sizePreserved}");

                            _logger.LogInformation(
                                "[WorldProxy][ENVELOPE] Prelude frame protected. ConnectionId={ConnectionId}, PlainOpcode=0x{PlainOpcode:X8}, ProtectedOpcode=0x{ProtectedOpcode:X8}, WorldCryptActive={WorldCryptActive}, SizePreserved={SizePreserved}",
                                connectionId,
                                frame.Opcode,
                                protectedOpcode,
                                bridgeState.IsRetailWorldCryptActive,
                                sizePreserved);
                        }

                        if (isAuthResponseFrame)
                        {
                            bool protectedEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(protectedFrame, out string protectedEnvelopeActual);
                            uint protectedSize = protectedEnvelopeOk
                                ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(0, 4))
                                : 0u;
                            bool sizePreserved = protectedEnvelopeOk &&
                                protectedSize == (uint)frame.BodyLength &&
                                protectedFrame.Length == frame.Frame.Length;
                            bridgeState.MarkTemporalInvariant(
                                name: "auth_response_encrypted_envelope_invariant",
                                passed: sizePreserved,
                                expected: "encrypted frame keeps plaintext size and total length (16+size), with 12-byte tag in header",
                                actual: $"{protectedEnvelopeActual};size_preserved={sizePreserved};expected_body={frame.BodyLength};protected_size={protectedSize};protected_bytes={protectedFrame.Length};plain_bytes={frame.Frame.Length}");

                            if (!sizePreserved)
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][ENVELOPE] Encrypted AUTH_RESPONSE envelope invariant failed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Actual={Actual}",
                                    connectionId,
                                    frame.Opcode,
                                    protectedEnvelopeActual);
                            }
                        }

                        if (frameIndex == 0)
                        {
                            deferredParity = HandshakeDiagnosticsWriters.EvaluateFirstDeferredFrameParity(
                                _options.ProbeFirstDeferredFrameParityFixturePath,
                                protectedFrame,
                                WorldGatewayPathResolver.ResolveProjectRoot());
                            bool parityConfigured = !string.IsNullOrWhiteSpace(_options.ProbeFirstDeferredFrameParityFixturePath);
                            bool parityPassed = !parityConfigured ||
                                string.Equals(deferredParity.Status, "match", StringComparison.OrdinalIgnoreCase);
                            string parityExpected = parityConfigured
                                ? "first deferred protected frame should byte-match configured fixture"
                                : "fixture not configured; parity check is informational only";
                            string parityActual = $"status={deferredParity.Status};fixture={deferredParity.FixturePath ?? "<none>"};diff_offset={deferredParity.DiffOffset?.ToString(CultureInfo.InvariantCulture) ?? "<none>"};expected={deferredParity.ExpectedBytes ?? "<none>"};actual={deferredParity.ActualBytes ?? "<none>"}";
                            bridgeState.MarkTemporalInvariant(
                                name: "deferred_first_frame_fixture_parity",
                                passed: parityPassed,
                                expected: parityExpected,
                                actual: parityActual);

                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] First deferred frame evidence. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Counter={Counter}, Tag={Tag}, PlainSha256={PlainSha256}, ProtectedSha256={ProtectedSha256}, ParityStatus={ParityStatus}, ParityDiffOffset={ParityDiffOffset}, ParityFixture={ParityFixture}",
                                connectionId,
                                frame.Opcode,
                                serverCounterUsed,
                                protectedTagHex,
                                plainSha256,
                                protectedSha256,
                                deferredParity.Status,
                                deferredParity.DiffOffset,
                                deferredParity.FixturePath ?? "<none>");
                        }

                        writer.Write(protectedFrame);
                        bytesWritten += protectedFrame.Length;

                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Sent deferred frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, BodyLength={BodyLength}, FrameBytes={FrameBytes}, Counter={Counter}, Tag={Tag}",
                            connectionId,
                            frameIndex + 1,
                            deferredFrames.Count,
                            frame.Opcode,
                            frame.BodyLength,
                            protectedFrame.Length,
                            serverCounterUsed,
                            protectedTagHex);

                        bridgeState.MarkDeferredFrameSent(
                            frameIndex + 1,
                            deferredFrames.Count,
                            frame.Opcode,
                            frame.BodyLength,
                            protectedFrame.Length,
                            serverCounterUsed,
                            plainSha256,
                            protectedSha256,
                            protectedTagHex,
                            deferredParity);

                        FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                        if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
                        {
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Deferred frame flush interrupted. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}",
                                connectionId,
                                frameIndex + 1,
                                deferredFrames.Count,
                                frame.Opcode);

                            deferredInterrupted = true;
                            break;
                        }
                    }

                    if (deferredInterrupted)
                    {
                        return new AckGateDeferredFlushResult(ShouldTerminateConnection: true, ShouldBreakRelay: false, BytesWritten: bytesWritten);
                    }

                    bridgeState.TryTransitionStage(
                        BridgeStage.BOOTSTRAP_FLUSHED,
                        "Deferred post-auth bootstrap flushed after ACK gate.");

                    if (_options.ProbeExplicitBootstrapFlushMarker)
                    {
                        bridgeState.MarkTemporalInvariant(
                            name: "bootstrap_flush_marker_explicit",
                            passed: true,
                            expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                            actual: $"path=protected_frames;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                            connectionId,
                            "protected_frames",
                            deferredPayload.Length,
                            stagedOpcodes);
                    }
                }
            }
        }

        return new AckGateDeferredFlushResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }
}
