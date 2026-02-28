using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private AuthBridgeHandlingResult? TryHandleAcoreToRetailAuthChallengeBridge(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        bool firstAcoreChallengeBridged,
        bool firstRetailAuthSessionBridged)
    {
        long bytesWritten = 0;
        bool handledByBridge = false;

        if (direction != "world->client" ||
            !_options.EnableAcoreToRetailAuthChallengeBridgeProbe ||
            firstAcoreChallengeBridged ||
            !RetailAuthChallengeBuilder.TryBuildFromAcore(
                buffer,
                _options.RetailAuthChallengeRandomizeDosBlock,
                out byte[] retailFrame,
                out int consumedBytes,
                out RetailAuthChallengeProof authChallengeProof))
        {
            return null;
        }

        firstAcoreChallengeBridged = true;
        handledByBridge = true;

        if (_options.ProbeRetailAuthChallengeCountAsPreAckWorldFrame)
        {
            if (!bridgeState.TryProtectRetailServerFrame(
                    retailFrame,
                    out byte[] protectedAuthChallengeFrame,
                    out _,
                    out string? protectError))
            {
                _logger.LogWarning(
                    "[WorldProxy][CRYPT] Failed to protect bridged Retail auth challenge frame. ConnectionId={ConnectionId}, Error={Error}",
                    connectionId,
                    protectError ?? "<unknown>");
                return new AuthBridgeHandlingResult(
                    handledByBridge,
                    firstAcoreChallengeBridged,
                    firstRetailAuthSessionBridged,
                    bytesWritten,
                    ShouldTerminateConnection: true);
            }

            writer.Write(protectedAuthChallengeFrame);
            bytesWritten += protectedAuthChallengeFrame.Length;
        }
        else
        {
            writer.Write(retailFrame);
            bytesWritten += retailFrame.Length;
        }

        _logger.LogInformation(
            "[WorldProxy][BRIDGE] Translated first AC auth challenge to Retail frame. ConnectionId={ConnectionId}, InBytes={InBytes}, OutBytes={OutBytes}",
            connectionId,
            consumedBytes,
            retailFrame.Length);

        if (_options.EnableProofPack)
        {
            try
            {
                AuthChallengeProofArtifacts artifacts = HandshakeDiagnosticsWriters.WriteAuthChallengeProofPack(
                    connectionId,
                    WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                    authChallengeProof);
                _logger.LogInformation(
                    "[WorldProxy][PROOF] Auth challenge proof written. ConnectionId={ConnectionId}, Hex={HexPath}, Json={JsonPath}",
                    connectionId,
                    artifacts.HexPath,
                    artifacts.MetadataJsonPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                _logger.LogWarning(
                    ex,
                    "[WorldProxy][PROOF] Failed to write auth challenge proof. ConnectionId={ConnectionId}",
                    connectionId);
            }
        }

        if (buffer.Length > consumedBytes)
        {
            foreach (ReadOnlyMemory<byte> segment in buffer.Slice(consumedBytes))
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
