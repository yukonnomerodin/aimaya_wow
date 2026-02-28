using System;
using System.Buffers;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class RetailPostAuthClientTranslator
    {
        private bool TryKickGlueResponseTurn(IBufferWriter<byte> output, uint triggerOpcode, out long bytesWritten)
        {
            bytesWritten = 0;

            bool bypassThrottle = ShouldBypassGlueKickThrottle(triggerOpcode);
            if (!bypassThrottle &&
                _glueSyntheticCharEnumKickMinIntervalMs > 0 &&
                _lastGlueSyntheticKickUnixMs != long.MinValue)
            {
                long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                long elapsedMs = nowUnixMs - _lastGlueSyntheticKickUnixMs;
                if (elapsedMs >= 0 && elapsedMs < _glueSyntheticCharEnumKickMinIntervalMs)
                {
                    int waitMs = checked((int)(_glueSyntheticCharEnumKickMinIntervalMs - elapsedMs));
                    _onGlueSyntheticKickSuppressed?.Invoke(triggerOpcode, waitMs);
                    return true;
                }
            }

            if (!_bridgeState.TryArmPendingGlueKick())
            {
                return true;
            }

            bool forwarded = PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                _authCrypt,
                WorldGatewayOpcodes.AcoreCmsgCharEnum,
                ReadOnlySpan<byte>.Empty,
                output,
                out bytesWritten);
            if (forwarded)
            {
                _lastGlueSyntheticKickUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            }

            return forwarded;
        }

        private static bool ShouldBypassGlueKickThrottle(uint triggerOpcode)
        {
            return triggerOpcode == WorldGatewayOpcodes.RetailCmsgDbQueryBulk ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgBattlenetRequest ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgServerTimeOffsetRequest ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgHotfixRequest ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgBattlePayGetPurchaseList ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgBattlePayGetProductList ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgUpdateVasPurchaseStates ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgQuickJoinAutoAcceptRequests ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgGetLastCatalogFetch ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgSocialContractRequest ||
                   triggerOpcode == WorldGatewayOpcodes.RetailCmsgGetUndeleteCharacterCooldownStatus;
        }
    }
}
