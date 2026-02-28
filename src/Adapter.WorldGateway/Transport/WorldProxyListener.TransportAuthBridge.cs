using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct AuthBridgeHandlingResult(
        bool HandledByBridge,
        bool FirstAcoreChallengeBridged,
        bool FirstRetailAuthSessionBridged,
        long BytesWritten,
        bool ShouldTerminateConnection);

    private async ValueTask<AuthBridgeHandlingResult> TryHandleAuthBridgeAsync(
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

        if (direction == "world->client" &&
            _options.EnableAcoreToRetailAuthChallengeBridgeProbe &&
            !firstAcoreChallengeBridged &&
            RetailAuthChallengeBuilder.TryBuildFromAcore(
                buffer,
                _options.RetailAuthChallengeRandomizeDosBlock,
                out byte[] retailFrame,
                out int consumedBytes,
                out RetailAuthChallengeProof authChallengeProof))
        {
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

        if (direction == "client->world" &&
            _options.EnableRetailToAcoreAuthSessionBridge &&
            !firstRetailAuthSessionBridged &&
            bridgeState.TryGetAcoreAuthSeed(out uint authSeed) &&
            RetailAuthSessionParser.TryParseRetailAuthSessionFrame(
                buffer,
                WorldGatewayOpcodes.RetailCmsgAuthSession,
                WorldGatewayProtocolConstants.RetailAuthFixedPayloadBytes,
                out RetailAuthSessionFrame retailAuthFrame))
        {
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
            if (bridgeState.TryGetAcoreServerChallenge(out byte[] serverChallenge))
            {
                if (EnterEncryptedModeFramePreparer.TryPrepareRetailEnterEncryptedModeFrame(
                    _options,
                    bridge.SessionKey,
                    bridge.BnetKeyData64,
                    retailAuthFrame.LocalChallenge32,
                    serverChallenge,
                    defaultRetailOpcode: _enterEncryptedModeOpcode,
                    out byte[] enterEncryptedModeFrame,
                    out uint enterEncryptedModeOpcodeUsed,
                    out string? enterEncryptedModeError,
                    out string keySource,
                    out string wireFormat,
                    out byte[] retailWorldEncryptKey32,
                    out EnterEncryptedModeProof proof))
                {
                    if (_options.EnterEncryptedModeParityGateEnabled)
                    {
                        string runlogsDir = WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options);
                        string projectRoot = WorldGatewayPathResolver.ResolveProjectRoot();
                        EnterEncryptedPayloadParityResult parity = HandshakeDiagnosticsWriters.EvaluateEnterEncryptedPayloadParity(
                            _options,
                            enterEncryptedModeFrame.AsSpan(20),
                            runlogsDir,
                            projectRoot);
                        if (!parity.FixtureFound)
                        {
                            _logger.LogWarning(
                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE fixture is unavailable. Gate skipped for this run. ConnectionId={ConnectionId}, FixturePath={FixturePath}, Error={Error}",
                                connectionId,
                                parity.FixturePath,
                                parity.Error ?? "<unknown>");
                        }
                        else if (!parity.PayloadMatch)
                        {
                            _logger.LogError(
                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload mismatch. ConnectionId={ConnectionId}, FixturePath={FixturePath}, ExpectedLen={ExpectedLen}, ActualLen={ActualLen}, DiffCount={DiffCount}, FirstDiffIndex={FirstDiffIndex}, Expected=0x{ExpectedByte:X2}, Actual=0x{ActualByte:X2}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}. Closing connection.",
                                connectionId,
                                parity.FixturePath,
                                parity.ExpectedLength,
                                parity.ActualLength,
                                parity.DiffCount,
                                parity.FirstDiffIndex ?? -1,
                                parity.FirstExpectedByte ?? (byte)0,
                                parity.FirstActualByte ?? (byte)0,
                                parity.SignatureBytesIgnored,
                                parity.SignatureOffset ?? -1,
                                parity.SignatureBytes);
                            return new AuthBridgeHandlingResult(
                                handledByBridge,
                                firstAcoreChallengeBridged,
                                firstRetailAuthSessionBridged,
                                bytesWritten,
                                ShouldTerminateConnection: true);
                        }
                        else
                        {
                            _logger.LogInformation(
                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload parity passed. ConnectionId={ConnectionId}, FixturePath={FixturePath}, PayloadBytes={PayloadBytes}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}",
                                connectionId,
                                parity.FixturePath,
                                parity.ActualLength,
                                parity.SignatureBytesIgnored,
                                parity.SignatureOffset ?? -1,
                                parity.SignatureBytes);
                        }
                    }

                    bridgeState.TrySetRetailEnterEncryptedModeFrame(enterEncryptedModeFrame);
                    if (retailWorldEncryptKey32.Length == 32)
                    {
                        bridgeState.TrySetRetailWorldEncryptKey(retailWorldEncryptKey32);
                    }
                    else
                    {
                        _logger.LogWarning(
                            "[WorldProxy][BRIDGE] Retail world encrypt key is unavailable. Post-ACK world packet crypto cannot be enabled. ConnectionId={ConnectionId}, KeyBytes={KeyBytes}, KeySource={KeySource}",
                            connectionId,
                            retailWorldEncryptKey32.Length,
                            keySource);
                    }

                    _logger.LogInformation(
                        "[WorldProxy][BRIDGE] Prepared Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, PayloadBytes={PayloadBytes}, KeySource={KeySource}, WireFormat={WireFormat}, RegionGroup={RegionGroup}, IncludeRegionGroup={IncludeRegionGroup}, Enabled={Enabled}, EnabledAsByte={EnabledAsByte}, PreferBnetKeyData={PreferBnetKeyData}",
                        connectionId,
                        enterEncryptedModeOpcodeUsed,
                        enterEncryptedModeFrame.Length - 20,
                        keySource,
                        wireFormat,
                        _options.EnterEncryptedModeRegionGroup,
                        _options.EnterEncryptedModeIncludeRegionGroup,
                        _options.EnterEncryptedModeEnabled,
                        _options.EnterEncryptedModeEnabledAsByte,
                        _options.EnterEncryptedModePreferBnetKeyData);

                    if (_options.EnableProofPack)
                    {
                        try
                        {
                            ProofPackArtifacts artifacts = HandshakeDiagnosticsWriters.WriteEnterEncryptedProofPack(
                                connectionId,
                                _options,
                                proof,
                                bridge.AccountId,
                                WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                                WorldGatewayPathResolver.ResolveProjectRoot());
                            bridgeState.SetProofPackArtifacts(artifacts.HexPath, artifacts.MetadataJsonPath, artifacts.DiffPath);
                            _logger.LogInformation(
                                "[WorldProxy][PROOF] Proof pack written. ConnectionId={ConnectionId}, Hex={HexPath}, Json={JsonPath}, Diff={DiffPath}",
                                connectionId,
                                artifacts.HexPath,
                                artifacts.MetadataJsonPath,
                                artifacts.DiffPath);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                        {
                            _logger.LogWarning(
                                ex,
                                "[WorldProxy][PROOF] Failed to write proof pack artifacts. ConnectionId={ConnectionId}",
                                connectionId);
                        }
                    }
                }
                else
                {
                    _logger.LogWarning(
                        "[WorldProxy][BRIDGE] Failed to build Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Error={Error}",
                        connectionId,
                        enterEncryptedModeError ?? "<unknown>");
                }
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

        return new AuthBridgeHandlingResult(
            handledByBridge,
            firstAcoreChallengeBridged,
            firstRetailAuthSessionBridged,
            bytesWritten,
            ShouldTerminateConnection: false);
    }
}
