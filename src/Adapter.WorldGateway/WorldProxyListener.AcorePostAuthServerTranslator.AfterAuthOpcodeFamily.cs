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

            if (opcode == WorldGatewayOpcodes.AcoreSmsgPong)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgPong, payload);
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == WorldGatewayOpcodes.AcoreSmsgTimeSyncRequest)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgTimeSyncRequest, payload);
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == WorldGatewayOpcodes.AcoreSmsgWardenData)
            {
                if (_forwardAcoreWardenAsRetailWarden3Data)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgWarden3Data, payload);
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

            if (opcode == WorldGatewayOpcodes.AcoreSmsgAddonInfo)
            {
                if (_forwardAcoreAddonInfoAsRetailAddonListRequest)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgAddonListRequest, payload);
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
                }

                // Same as Warden: AC legacy addon blob does not match retail parser expectations.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (opcode == WorldGatewayOpcodes.AcoreSmsgClientCacheVersion)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgCacheVersion, payload);
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == WorldGatewayOpcodes.AcoreSmsgTutorialFlags)
            {
                if (_forwardAcoreTutorialFlagsAsRetailTutorialFlags)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgTutorialFlags, payload);
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