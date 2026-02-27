using System;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private void TryBufferOrDropPreAuthFrame(ushort opcode, ReadOnlySpan<byte> payload)
        {
            if (_bufferedBeforeAuth.Count >= WorldProxyRuntimeConstants.MaxBufferedFramesBeforeAuth ||
                _bufferedBeforeAuthBytes + payload.Length > WorldProxyRuntimeConstants.MaxBufferedBytesBeforeAuth)
            {
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return;
            }

            byte[] payloadCopy = GC.AllocateUninitializedArray<byte>(payload.Length);
            payload.CopyTo(payloadCopy);
            _bufferedBeforeAuth.Add(new BufferedServerFrame(opcode, payloadCopy));
            _bufferedBeforeAuthBytes += payload.Length;
        }
    }
}
