using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryTranslateDecodedFrame(ushort opcode, ReadOnlySpan<byte> payload, IBufferWriter<byte> output, out long bytesWritten, out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (!_bridgeState.ValidateServerOpcode(opcode, _strictStageEnforcement, out string? stageError))
            {
                error = stageError;
                return false;
            }

            // Retail client expects auth response first. Buffer AC side packets that arrive before it,
            // then flush them in order right after auth response has been forwarded.
            if (!_authResponseForwarded)
            {
                if (opcode != AcoreOpcodeSmsgAuthResponse)
                {
                    TryBufferOrDropPreAuthFrame(opcode, payload);
                    return true;
                }

                if (!TryBuildMappedAuthResponseFrame(payload, out byte[] mapped, out bool authResponseAlreadyCompressed, out error))
                {
                    return false;
                }

                if (!TryApplyAuthResponseCompressionIfNeeded(mapped, authResponseAlreadyCompressed, out mapped, out error))
                {
                    return false;
                }

                return TryStageAndFlushAuthBootstrap(mapped, output, ref bytesWritten, out error);
            }

            return TryTranslateAfterAuth(opcode, payload, output, out bytesWritten, out error);
        }

    }
}
