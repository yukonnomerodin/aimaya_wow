using System;
using System.Buffers;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryTranslateAuthResponseDuringPreAuth(
            ReadOnlySpan<byte> payload,
            IBufferWriter<byte> output,
            ref long bytesWritten,
            out string? error)
        {
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
    }
}
