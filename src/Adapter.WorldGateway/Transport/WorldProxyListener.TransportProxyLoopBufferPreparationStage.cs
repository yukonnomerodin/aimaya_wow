using System.Buffers;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void RunProxyBufferPreparationStage(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        bool waitForEnterEncryptedAckGate,
        TransportProxyLoopState loopState)
    {
        if (_options.EnableFirstPacketDump && !loopState.FirstChunkDumped)
        {
            loopState.FirstChunkDumped = true;
            int maxBytes = _options.FirstPacketDumpBytes <= 0
                ? WorldProxyRuntimeConstants.DefaultDumpBytes
                : _options.FirstPacketDumpBytes;
            _logger.LogInformation(
                "[WorldProxy][DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                connectionId,
                direction,
                buffer.Length,
                RetailFrameCodec.ToHex(buffer, maxBytes));

            if (RetailFrameCodec.TryDecodeFirstHeader(buffer, out DumpHeaderDecode decode))
            {
                _logger.LogInformation(
                    "[WorldProxy][DUMP-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, FrameBytes={FrameBytes}, SizeBE={SizeBE}, SizeLE={SizeLE}, OpcodeLE=0x{OpcodeLE:X4}, OpcodeBE=0x{OpcodeBE:X4}, SizeBEMatches={SizeBEMatches}",
                    connectionId,
                    direction,
                    buffer.Length,
                    decode.SizeBE,
                    decode.SizeLE,
                    decode.OpcodeLE,
                    decode.OpcodeBE,
                    decode.SizeBEMatches);

                if (direction == "world->client" &&
                    decode.OpcodeLE == WorldGatewayOpcodes.AcoreSmsgAuthChallenge &&
                    AcoreAuthChallengeDumpDecoder.TryDecode(buffer, out AcoreAuthChallengeDump challenge))
                {
                    bridgeState.SetAcoreAuthSeed(challenge.AuthSeed);
                    bridgeState.SetAcoreServerChallenge(challenge.NewSeed);

                    _logger.LogInformation(
                        "[WorldProxy][DUMP-AC-AUTH-CHALLENGE] ConnectionId={ConnectionId}, DosChallenge={DosChallenge}, AuthSeed=0x{AuthSeed:X8}, NewSeed={NewSeedHex}",
                        connectionId,
                        challenge.DosChallenge,
                        challenge.AuthSeed,
                        challenge.NewSeedHex);
                }
            }
        }

        loopState.RetailPostAuthClientTranslator = EnsureRetailPostAuthClientTranslator(
            direction,
            loopState.RetailPostAuthClientTranslator,
            bridgeState,
            connectionId,
            downstreamKey);

        loopState.AcorePostAuthServerTranslator = EnsureAcorePostAuthServerTranslator(
            direction,
            loopState.AcorePostAuthServerTranslator,
            bridgeState,
            connectionId,
            waitForEnterEncryptedAckGate,
            onFrameDecoded: (opcode, payloadBytes) =>
            {
                // Limit frame spam while collecting first handshake map.
                if (loopState.AcoreServerFramesLogged < 32)
                {
                    loopState.AcoreServerFramesLogged++;
                    _logger.LogInformation(
                        "[WorldProxy][AC->CLIENT FRAME] ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                        connectionId,
                        opcode,
                        payloadBytes);
                }
            });

        if (direction == "world->client" &&
            !loopState.FirstPostAuthDumpedServer &&
            bridgeState.TryGetAcoreHeaderCrypt(out _))
        {
            loopState.FirstPostAuthDumpedServer = true;
            _logger.LogInformation(
                "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                connectionId,
                direction,
                buffer.Length,
                RetailFrameCodec.ToHex(
                    buffer,
                    Math.Max(WorldProxyRuntimeConstants.DefaultDumpBytes, _options.FirstPacketDumpBytes)));
        }

        if (direction == "client->world" &&
            !loopState.FirstPostAuthDumpedClient &&
            bridgeState.TryGetAcoreHeaderCrypt(out _))
        {
            loopState.FirstPostAuthDumpedClient = true;
            _logger.LogInformation(
                "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                connectionId,
                direction,
                buffer.Length,
                RetailFrameCodec.ToHex(
                    buffer,
                    Math.Max(WorldProxyRuntimeConstants.DefaultDumpBytes, _options.FirstPacketDumpBytes)));

            if (RetailFrameCodec.TryDecodeRetailWorldFrame(buffer, out uint retailBodyLength, out uint retailOpcode))
            {
                _logger.LogInformation(
                    "[WorldProxy][POSTAUTH-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, RetailBodyLength={RetailBodyLength}, RetailOpcode=0x{RetailOpcode:X8}",
                    connectionId,
                    direction,
                    retailBodyLength,
                    retailOpcode);
            }
        }
    }
}
