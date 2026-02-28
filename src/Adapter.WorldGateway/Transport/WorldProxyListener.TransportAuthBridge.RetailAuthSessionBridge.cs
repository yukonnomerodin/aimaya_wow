using System.Buffers;
using System.IO.Pipelines;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<AuthBridgeHandlingResult?> TryHandleRetailToAcoreAuthSessionBridgeAsync(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        bool firstAcoreChallengeBridged,
        bool firstRetailAuthSessionBridged,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;
        bool handledByBridge = false;

        if (direction != "client->world" ||
            !_options.EnableRetailToAcoreAuthSessionBridge ||
            firstRetailAuthSessionBridged ||
            !bridgeState.TryGetAcoreAuthSeed(out uint authSeed) ||
            !RetailAuthSessionParser.TryParseRetailAuthSessionFrame(
                buffer,
                WorldGatewayOpcodes.RetailCmsgAuthSession,
                WorldGatewayProtocolConstants.RetailAuthFixedPayloadBytes,
                out RetailAuthSessionFrame retailAuthFrame))
        {
            return null;
        }

        if (_options.ProbeRetailAuthSessionCountAsPreAckClientFrame)
        {
            byte[] retailAuthWireFrame = GC.AllocateUninitializedArray<byte>(retailAuthFrame.RawFrameBytes);
            buffer.Slice(0, retailAuthFrame.RawFrameBytes).CopyTo(retailAuthWireFrame);
            if (!bridgeState.TryDecryptRetailClientFrame(retailAuthWireFrame, out _, out string? decryptError))
            {
                _logger.LogWarning(
                    "[WorldProxy][CRYPT] Failed to count Retail CMSG_AUTH_SESSION as pre-ACK client frame. ConnectionId={ConnectionId}, Error={Error}",
                    connectionId,
                    decryptError ?? "<unknown>");
                return new AuthBridgeHandlingResult(
                    handledByBridge,
                    firstAcoreChallengeBridged,
                    firstRetailAuthSessionBridged,
                    bytesWritten,
                    ShouldTerminateConnection: true);
            }

            _logger.LogInformation(
                "[WorldProxy][HANDSHAKE] Counted Retail CMSG_AUTH_SESSION as pre-ACK client frame for counter continuity. ConnectionId={ConnectionId}, FrameBytes={FrameBytes}",
                connectionId,
                retailAuthFrame.RawFrameBytes);
        }

        AcoreAuthSessionBridgeResult? authBridgeResult = await TryBuildAcoreAuthSessionFrameAsync(
                authSeed,
                retailAuthFrame,
                bridgeState,
                cancellationToken)
            .ConfigureAwait(false);

        if (authBridgeResult is null)
        {
            _logger.LogWarning(
                "[WorldProxy][BRIDGE] Failed to translate Retail CMSG_AUTH_SESSION in strict mode. ConnectionId={ConnectionId}. Closing connection.",
                connectionId);

            return new AuthBridgeHandlingResult(
                handledByBridge,
                firstAcoreChallengeBridged,
                firstRetailAuthSessionBridged,
                bytesWritten,
                ShouldTerminateConnection: true);
        }

        AcoreAuthSessionBridgeResult bridge = authBridgeResult.Value;
        firstRetailAuthSessionBridged = true;
        handledByBridge = true;

        writer.Write(bridge.Frame);
        bytesWritten += bridge.Frame.Length;

        bridgeState.TrySetAcoreHeaderCrypt(bridge.HeaderCrypt);
        if (!TryPrepareEnterEncryptedModeAfterAuthBridge(
                connectionId,
                bridgeState,
                bridge,
                retailAuthFrame,
                out bool shouldTerminateConnection))
        {
            return new AuthBridgeHandlingResult(
                handledByBridge,
                firstAcoreChallengeBridged,
                firstRetailAuthSessionBridged,
                bytesWritten,
                ShouldTerminateConnection: shouldTerminateConnection);
        }

        _logger.LogInformation(
            "[WorldProxy][BRIDGE] Translated Retail CMSG_AUTH_SESSION to AC CMSG_AUTH_SESSION. ConnectionId={ConnectionId}, InBytes={InBytes}, OutBytes={OutBytes}, AccountId={AccountId}, AccountIdSource={AccountIdSource}, RegionId={RegionId}, BattlegroupId={BattlegroupId}, RetailRealmId=0x{RetailRealmId:X8}, AcoreRealmId={AcoreRealmId}",
            connectionId,
            retailAuthFrame.RawFrameBytes,
            bridge.Frame.Length,
            bridge.AccountId,
            bridge.AccountIdSource,
            retailAuthFrame.RegionId,
            retailAuthFrame.BattlegroupId,
            retailAuthFrame.RealmId,
            _options.AcoreRealmId);
        bridgeState.TryTransitionStage(
            BridgeStage.AUTH_SESSION_BRIDGED,
            "Retail CMSG_AUTH_SESSION translated to AC CMSG_AUTH_SESSION.");

        if (buffer.Length > retailAuthFrame.RawFrameBytes)
        {
            foreach (ReadOnlyMemory<byte> segment in buffer.Slice(retailAuthFrame.RawFrameBytes))
            {
                writer.Write(segment.Span);
                bytesWritten += segment.Length;
            }
        }

        return new AuthBridgeHandlingResult(
            handledByBridge,
            firstAcoreChallengeBridged,
            firstRetailAuthSessionBridged,
            bytesWritten,
            ShouldTerminateConnection: false);
    }
}
