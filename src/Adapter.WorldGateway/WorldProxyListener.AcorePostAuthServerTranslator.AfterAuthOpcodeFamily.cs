using System;
using System.Buffers;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryHandleAfterAuthOpcodeFamily(ushort opcode, ReadOnlySpan<byte> payload, IBufferWriter<byte> output, out long bytesWritten, out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (opcode == AcoreOpcodeSmsgPong)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgPong, payload);
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgTimeSyncRequest)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTimeSyncRequest, payload);
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgWardenData)
            {
                if (_forwardAcoreWardenAsRetailWarden3Data)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgWarden3Data, payload);
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
                }

                // Legacy AC Warden payload is not retail-compatible at this stage.
                // Drop until probe confirms mapping viability.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (opcode == AcoreOpcodeSmsgAddonInfo)
            {
                if (_forwardAcoreAddonInfoAsRetailAddonListRequest)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAddonListRequest, payload);
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
                }

                // Same as Warden: AC legacy addon blob does not match retail parser expectations.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (opcode == AcoreOpcodeSmsgClientCacheVersion)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgCacheVersion, payload);
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgTutorialFlags)
            {
                if (_forwardAcoreTutorialFlagsAsRetailTutorialFlags)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTutorialFlags, payload);
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
                }

                // Optional data; safe to suppress while auth bootstrap parity is incomplete.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (_loggedDroppedOpcodes.Add(opcode))
            {
                _onDroppedOpcode?.Invoke(opcode, payload.Length);
            }

            return true;
        }
    }
}
