using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Pipelines;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<DeferredBootstrapFlushResult> FlushDeferredBootstrapProtectedFramesAsync(
        uint connectionId,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        List<RetailFrameChunk> deferredFrames,
        byte[] deferredPayload,
        string stagedOpcodes,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;

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

                return new DeferredBootstrapFlushResult(
                    ShouldTerminateConnection: true,
                    ShouldBreakRelay: false,
                    BytesWritten: bytesWritten);
            }

            bool shouldComputeFrameHashes = _options.EnablePerFrameDeferredHashEvidence || frameIndex == 0;
            string plainSha256 = shouldComputeFrameHashes ? ComputeSha256Hex(frame.Frame) : "<skipped>";
            string protectedSha256 = shouldComputeFrameHashes ? ComputeSha256Hex(protectedFrame) : "<skipped>";
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
            return new DeferredBootstrapFlushResult(
                ShouldTerminateConnection: true,
                ShouldBreakRelay: false,
                BytesWritten: bytesWritten);
        }

        bridgeState.TryTransitionStage(
            BridgeStage.BOOTSTRAP_FLUSHED,
            "Deferred post-auth bootstrap flushed after ACK gate.");

        TryMarkExplicitBootstrapFlushMarker(
            connectionId,
            bridgeState,
            path: "protected_frames",
            deferredPayload.Length,
            stagedOpcodes);

        return new DeferredBootstrapFlushResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }

    private static string ComputeSha256Hex(ReadOnlySpan<byte> bytes)
    {
        Span<byte> hashBuffer = stackalloc byte[32];
        if (SHA256.TryHashData(bytes, hashBuffer, out int written) && written == hashBuffer.Length)
        {
            return Convert.ToHexString(hashBuffer);
        }

        return Convert.ToHexString(SHA256.HashData(bytes));
    }
}
