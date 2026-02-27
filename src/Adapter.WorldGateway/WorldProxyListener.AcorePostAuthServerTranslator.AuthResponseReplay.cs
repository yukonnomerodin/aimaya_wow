using System;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryBuildMappedAuthResponseFrame(
            ReadOnlySpan<byte> payload,
            out byte[] mapped,
            out bool authResponseAlreadyCompressed,
            out string? error)
        {
            mapped = Array.Empty<byte>();
            authResponseAlreadyCompressed = false;
            error = null;

            if (_probeAuthResponseReplayPayload.Length > 0)
            {
                return TryBuildReplayAuthResponseFrameFromProbe(
                    payload,
                    out mapped,
                    out authResponseAlreadyCompressed,
                    out error);
            }

            return AuthResponseFrameBuilder.TryBuildRetailAuthResponseFromAcore(
                payload,
                _probeAuthResponseResultOnly,
                _probeAuthResponseResultOnlyCode,
                _probeAuthResponseMinimalSuccessNoAccountData,
                _probeAuthResponseTwwAccountDataProfile,
                _probeAuthResponseTwwAddResultPrefix,
                _probeAuthResponseForceWaitInfoPresent,
                _probeAuthResponseForceCurrentBuildPresent,
                _probeAuthResponseAvailableClassesCardinality,
                _probeAuthResponseTwwClassMatrixRows,
                _probeAuthResponseTwwUseAcoreExpansionLevels,
                _authResponseFuzzMutation,
                _probeAuthResponseOpcode,
                _acoreRealmId,
                AuthResponseReplayCurrentBuildValue,
                out mapped,
                out error);
        }

        private bool TryBuildReplayAuthResponseFrameFromProbe(
            ReadOnlySpan<byte> payload,
            out byte[] mapped,
            out bool authResponseAlreadyCompressed,
            out string? error)
        {
            authResponseAlreadyCompressed = false;
            error = null;

            if (_probeAuthResponseReplayBisectionResultOnlyErrorOk)
            {
                Span<byte> resultOnlyPayload = stackalloc byte[sizeof(uint)];
                BinaryPrimitives.WriteUInt32LittleEndian(resultOnlyPayload, 0u); // ERROR_OK
                mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(_probeAuthResponseOpcode, resultOnlyPayload);
                return true;
            }

            ReadOnlySpan<byte> replayPayload = _probeAuthResponseReplayPayload;
            byte[]? patchedReplayPayload = null;
            if (_probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchExpansionLevelsFromAcoreAccount(
                        replayPayload,
                        payload,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload expansion levels.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchClassMatrixExpansionTripletsFromAcoreAccount(
                        replayPayload,
                        payload,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload class-matrix expansion triplets.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchClassMatrixCardinalityToRuntimeSubset(
                        replayPayload,
                        payload,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload class-matrix cardinality to runtime subset.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchCurrentBuildPresent)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchCurrentBuildPresent(
                        replayPayload,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload CurrentBuild optional block.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchWaitInfoPresent)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchWaitInfoPresent(
                        replayPayload,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload WaitInfo optional block.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchVirtualRealmEntryFromRuntimeRealm(
                        replayPayload,
                        _acoreRealmId,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload virtual realm entry.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchTopVirtualRealmAddressFromRuntimeRealm(
                        replayPayload,
                        _acoreRealmId,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload top virtual realm address.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            if (_probeAuthResponseReplayPatchTimeToNow)
            {
                if (!AuthResponseReplayPatchHelpers.TryPatchTimeUnixNow(
                        replayPayload,
                        out patchedReplayPayload,
                        out string? patchError))
                {
                    error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload time field.";
                    mapped = Array.Empty<byte>();
                    return false;
                }

                replayPayload = patchedReplayPayload;
            }

            mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(_probeAuthResponseOpcode, replayPayload);

            if (_probeAuthResponseReplayCompressedPayload.Length > 0)
            {
                mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(
                    RetailOpcodeSmsgCompressedPacket,
                    _probeAuthResponseReplayCompressedPayload);
                authResponseAlreadyCompressed = true;
            }

            return true;
        }
    }
}
