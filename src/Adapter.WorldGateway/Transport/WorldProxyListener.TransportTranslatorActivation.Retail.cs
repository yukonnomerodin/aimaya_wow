using System.Globalization;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private RetailPostAuthClientTranslator? EnsureRetailPostAuthClientTranslator(
        string direction,
        RetailPostAuthClientTranslator? retailPostAuthClientTranslator,
        WorldProxyBridgeState bridgeState,
        uint connectionId,
        string downstreamKey)
    {
        if (direction != "client->world" ||
            retailPostAuthClientTranslator is not null ||
            !bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt sendCrypt))
        {
            return retailPostAuthClientTranslator;
        }

        retailPostAuthClientTranslator = new RetailPostAuthClientTranslator(
            sendCrypt,
            bridgeState,
            strictStageEnforcement: _protocolOptions.StrictStageEnforcement,
            onLogDisconnect: reason =>
            {
                bridgeState.SetLogDisconnectReason(reason);
                if (ReconnectCooldownHelpers.TryArm(
                        _reconnectCooldownUntilByKey,
                        _options.ReconnectCooldownMs,
                        downstreamKey,
                        out long cooldownUntilUnixMs))
                {
                    _logger.LogInformation(
                        "[WorldProxy][ANTISPAM] Reconnect cooldown armed. DownstreamKey={DownstreamKey}, CooldownMs={CooldownMs}, Source={Source}, Reason={Reason}, UntilUnixMs={UntilUnixMs}",
                        downstreamKey,
                        _options.ReconnectCooldownMs,
                        "cmsg_log_disconnect",
                        reason.ToString(CultureInfo.InvariantCulture),
                        cooldownUntilUnixMs);
                }

                bridgeState.MarkClientRequestedDisconnect();
                _logger.LogInformation(
                    "[WorldProxy][MAP] Retail CMSG_LOG_DISCONNECT received. ConnectionId={ConnectionId}, Reason={Reason}",
                    connectionId,
                    reason);
            },
            onEnumCharactersRequest: () =>
            {
                if (!bridgeState.TryTransitionStage(
                        BridgeStage.CHAR_ENUM_REQUESTED,
                        "Retail CMSG_ENUM_CHARACTERS forwarded."))
                {
                    _logger.LogWarning(
                        "[WorldProxy][STATE] CHAR_ENUM_REQUESTED transition rejected. ConnectionId={ConnectionId}, Stage={Stage}",
                        connectionId,
                        bridgeState.CurrentStage);
                }
            },
            onEnterEncryptedModeAck: () =>
            {
                bool signaled = bridgeState.SignalEnterEncryptedAck();
                bridgeState.MarkEnterEncryptedAckObserved();
                if (bridgeState.CurrentStage < BridgeStage.BOOTSTRAP_FLUSHED)
                {
                    bridgeState.TryTransitionStage(
                        BridgeStage.WORLD_CRYPT_ACTIVE,
                        "Retail CMSG_ENTER_ENCRYPTED_MODE_ACK observed.");
                }

                if (_options.EnableRetailWorldPacketCryptOnAck)
                {
                    if (bridgeState.TryEnableRetailWorldCrypt(out string? enableError))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][CRYPT] Retail world packet crypt enabled on ACK. ConnectionId={ConnectionId}",
                            connectionId);
                    }
                    else
                    {
                        _logger.LogWarning(
                            "[WorldProxy][CRYPT] Failed to enable Retail world packet crypt on ACK. ConnectionId={ConnectionId}, Error={Error}",
                            connectionId,
                            enableError ?? "<unknown>");
                    }
                }
                else
                {
                    _logger.LogInformation(
                        "[WorldProxy][CRYPT] Retail world packet crypt-on-ACK disabled by config. ConnectionId={ConnectionId}",
                        connectionId);
                }

                _logger.LogInformation(
                    "[WorldProxy][MAP] Retail CMSG_ENTER_ENCRYPTED_MODE_ACK received. ConnectionId={ConnectionId}, Signaled={Signaled}, Awaiting={Awaiting}",
                    connectionId,
                    signaled,
                    bridgeState.IsAwaitingEnterEncryptedAck);
            },
            onPostAckNonAckClientFrame: opcode =>
            {
                bool signaled = bridgeState.RegisterPostAckNonAckBootstrapTrigger(opcode);
                if (signaled)
                {
                    _logger.LogInformation(
                        "[WorldProxy][HANDSHAKE] Post-ACK non-ACK client frame observed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}",
                        connectionId,
                        opcode);
                }
            },
            glueSyntheticCharEnumKickMinIntervalMs: _options.GlueSyntheticCharEnumKickMinIntervalMs,
            onGlueSyntheticKickSuppressed: (opcode, waitMs) =>
            {
                _logger.LogInformation(
                    "[WorldProxy][GLUE] Synthetic CHAR_ENUM kick throttled. ConnectionId={ConnectionId}, TriggerOpcode=0x{Opcode:X8}, WaitMs={WaitMs}",
                    connectionId,
                    opcode,
                    waitMs);
            });
        _logger.LogInformation(
            "[WorldProxy][MAP] Retail->AC post-auth translator enabled. ConnectionId={ConnectionId}",
            connectionId);

        return retailPostAuthClientTranslator;
    }
}
