using System;
using System.Buffers;

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
                if (opcode != WorldGatewayOpcodes.AcoreSmsgAuthResponse)
                {
                    TryBufferOrDropPreAuthFrame(opcode, payload);
                    return true;
                }

                return TryTranslateAuthResponseDuringPreAuth(payload, output, ref bytesWritten, out error);
            }

            return TryTranslateAfterAuth(opcode, payload, output, out bytesWritten, out error);
        }

    }
}