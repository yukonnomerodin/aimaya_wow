using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private bool TryPrepareEnterEncryptedModeAfterAuthBridge(
        uint connectionId,
        WorldProxyBridgeState bridgeState,
        in AcoreAuthSessionBridgeResult bridge,
        in RetailAuthSessionFrame retailAuthFrame,
        out bool shouldTerminateConnection)
    {
        shouldTerminateConnection = false;

        if (!bridgeState.TryGetAcoreServerChallenge(out byte[] serverChallenge))
        {
            return true;
        }

        if (!EnterEncryptedModeFramePreparer.TryPrepareRetailEnterEncryptedModeFrame(
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
            _logger.LogWarning(
                "[WorldProxy][BRIDGE] Failed to build Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Error={Error}",
                connectionId,
                enterEncryptedModeError ?? "<unknown>");
            return true;
        }

        if (!TryValidateEnterEncryptedModeParityGate(
                connectionId,
                enterEncryptedModeFrame,
                out shouldTerminateConnection))
        {
            return false;
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

        return true;
    }

    private bool TryValidateEnterEncryptedModeParityGate(
        uint connectionId,
        byte[] enterEncryptedModeFrame,
        out bool shouldTerminateConnection)
    {
        shouldTerminateConnection = false;

        if (!_options.EnterEncryptedModeParityGateEnabled)
        {
            return true;
        }

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
            return true;
        }

        if (!parity.PayloadMatch)
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
            shouldTerminateConnection = true;
            return false;
        }

        _logger.LogInformation(
            "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload parity passed. ConnectionId={ConnectionId}, FixturePath={FixturePath}, PayloadBytes={PayloadBytes}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}",
            connectionId,
            parity.FixturePath,
            parity.ActualLength,
            parity.SignatureBytesIgnored,
            parity.SignatureOffset ?? -1,
            parity.SignatureBytes);

        return true;
    }
}
