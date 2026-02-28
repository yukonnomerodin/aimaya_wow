using System.IO.Pipelines;
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
                DeferredBootstrapFlushResult deferredFlushResult = await TryFlushDeferredBootstrapPayloadAsync(
                        connectionId,
                        writer,
                        bridgeState,
                        deferredPayload,
                        stagedOpcodes,
                        cancellationToken)
                    .ConfigureAwait(false);
                bytesWritten += deferredFlushResult.BytesWritten;
                if (deferredFlushResult.ShouldTerminateConnection)
                {
                    return new AckGateDeferredFlushResult(ShouldTerminateConnection: true, ShouldBreakRelay: false, BytesWritten: bytesWritten);
                }

                if (deferredFlushResult.ShouldBreakRelay)
                {
                    return new AckGateDeferredFlushResult(ShouldTerminateConnection: false, ShouldBreakRelay: true, BytesWritten: bytesWritten);
                }
            }
        }

        return new AckGateDeferredFlushResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }
}
