using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        public AcorePostAuthServerTranslator(
            AuthCrypt authCrypt,
            WorldProxyBridgeState bridgeState,
            bool strictStageEnforcement = true,
            bool waitForEnterEncryptedAckGate = false,
            bool suppressPostAuthBootstrapForProbe = false,
            bool probeBareAuthResponseOnly = false,
            bool probeAuthResponseResultOnly = false,
            uint probeAuthResponseResultOnlyCode = 0,
            bool probeAuthResponseMinimalSuccessNoAccountData = false,
            bool probeAuthResponseTwwAccountDataProfile = false,
            bool probeAuthResponseTwwAddResultPrefix = false,
            bool probeAuthResponseForceWaitInfoPresent = false,
            bool probeAuthResponseForceCurrentBuildPresent = false,
            int probeAuthResponseAvailableClassesCardinality = 1,
            int probeAuthResponseTwwClassMatrixRows = 0,
            bool probeAuthResponseTwwUseAcoreExpansionLevels = false,
            bool probeInsertRetailSequencePreludeBeforeAuthResponse = false,
            bool probeInsertRetailSequencePreludeAfterAuthResponse = false,
            bool probeReorderFirstDeferredFrameAfterPrelude = false,
            bool probeFeatureSystemStatusGlueScreenTrinitySemantics = false,
            bool probeCompressAuthResponseAsSmsgCompressedPacket = false,
            bool probeCompressedAuthResponseForceEnvelope = false,
            bool probeCompressedAuthResponseUseRawDeflate = false,
            bool probeCompressedAuthResponseUseStatefulDeflateSyncFlush = false,
            int probeCompressedAuthResponseRawDeflateLevel = -1,
            bool probeCompressedAuthResponseChecksumPayloadOnly = false,
            long probeCompressedAuthResponseChecksumSeed = WorldGatewayProtocolConstants.TrinityCompressionAdlerSeed,
            bool probeCompressedAuthResponseCompressedChecksumIncludeMetadata = false,
            byte[]? probeRetailSequencePreludePayload = null,
            AuthResponseFuzzMutation authResponseFuzzMutation = default,
            uint probeAuthResponseOpcode = WorldGatewayOpcodes.RetailSmsgAuthResponse,
            byte[]? probeAuthResponseReplayPayload = null,
            byte[]? probeAuthResponseReplayCompressedPayload = null,
            bool probeAuthResponseReplayPatchTimeToNow = false,
            bool probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount = false,
            bool probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount = false,
            bool probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset = false,
            bool probeAuthResponseReplayPatchCurrentBuildPresent = false,
            bool probeAuthResponseReplayPatchWaitInfoPresent = false,
            bool probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm = false,
            bool probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm = false,
            bool probeAuthResponseReplayBisectionResultOnlyErrorOk = false,
            byte[]? probeSetTimeZoneInformationPayload = null,
            byte[]? probeFeatureSystemStatusGlueScreenPayload = null,
            byte[]? probeMirrorVarsPayload = null,
            byte[]? probeCacheVersionPayload = null,
            byte[]? probeAvailableHotfixesPayload = null,
            byte[]? probeAccountDataTimesPayload = null,
            byte[]? probeTutorialFlagsPayload = null,
            byte[]? probeBattleNetConnectionStatusPayload = null,
            uint acoreRealmId = 1,
            bool controlledUnlockEmptyCharEnumEnabled = false,
            bool forwardAcoreWardenAsRetailWarden3Data = false,
            bool forwardAcoreAddonInfoAsRetailAddonListRequest = false,
            bool forwardAcoreTutorialFlagsAsRetailTutorialFlags = false,
            Func<byte[]?>? getEnterEncryptedModeFrame = null,
            Action<byte[], string>? onDeferredBootstrapPrepared = null,
            Action? onEnterEncryptedModeSent = null,
            Action<string>? onEnterEncryptedAwaitStart = null,
            Action<int, string>? onBootstrapFlushedWithoutAck = null,
            Action<int, string>? onBootstrapSuppressedForProbe = null,
            Action? onCharEnumReceived = null,
            Action<int, int>? onControlledUnlockApplied = null,
            Action<ushort, int>? onFrameDecoded = null,
            Action<ushort, int>? onDroppedOpcode = null)
        {
            _authCrypt = authCrypt ?? throw new ArgumentNullException(nameof(authCrypt));
            _bridgeState = bridgeState ?? throw new ArgumentNullException(nameof(bridgeState));
            _strictStageEnforcement = strictStageEnforcement;
            _waitForEnterEncryptedAckGate = waitForEnterEncryptedAckGate;
            _probeBareAuthResponseOnly = probeBareAuthResponseOnly;
            _probeAuthResponseResultOnly = probeAuthResponseResultOnly;
            _probeAuthResponseResultOnlyCode = probeAuthResponseResultOnlyCode;
            _probeAuthResponseMinimalSuccessNoAccountData = probeAuthResponseMinimalSuccessNoAccountData;
            _probeAuthResponseTwwAccountDataProfile = probeAuthResponseTwwAccountDataProfile;
            _probeAuthResponseTwwAddResultPrefix = probeAuthResponseTwwAddResultPrefix;
            _probeAuthResponseForceWaitInfoPresent = probeAuthResponseForceWaitInfoPresent;
            _probeAuthResponseForceCurrentBuildPresent = probeAuthResponseForceCurrentBuildPresent;
            _probeAuthResponseAvailableClassesCardinality = Math.Clamp(probeAuthResponseAvailableClassesCardinality, 1, 13);
            _probeAuthResponseTwwClassMatrixRows = Math.Clamp(probeAuthResponseTwwClassMatrixRows, 0, AuthResponseClassMatrixHelpers.LegacyRowCount);
            _probeAuthResponseTwwUseAcoreExpansionLevels = probeAuthResponseTwwUseAcoreExpansionLevels;
            _probeInsertRetailSequencePreludeBeforeAuthResponse = probeInsertRetailSequencePreludeBeforeAuthResponse;
            _probeInsertRetailSequencePreludeAfterAuthResponse =
                probeInsertRetailSequencePreludeAfterAuthResponse &&
                !probeInsertRetailSequencePreludeBeforeAuthResponse;
            _probeReorderFirstDeferredFrameAfterPrelude =
                probeReorderFirstDeferredFrameAfterPrelude &&
                _probeInsertRetailSequencePreludeAfterAuthResponse;
            _probeFeatureSystemStatusGlueScreenTrinitySemantics = probeFeatureSystemStatusGlueScreenTrinitySemantics;
            _probeCompressAuthResponseAsSmsgCompressedPacket = probeCompressAuthResponseAsSmsgCompressedPacket;
            _probeCompressedAuthResponseForceEnvelope = probeCompressedAuthResponseForceEnvelope;
            _probeCompressedAuthResponseUseRawDeflate = probeCompressedAuthResponseUseRawDeflate;
            _probeCompressedAuthResponseUseStatefulDeflateSyncFlush = probeCompressedAuthResponseUseStatefulDeflateSyncFlush;
            _probeCompressedAuthResponseRawDeflateLevel = RetailCompressionCodec.NormalizeDeflateLevel(probeCompressedAuthResponseRawDeflateLevel);
            _probeCompressedAuthResponseChecksumPayloadOnly = probeCompressedAuthResponseChecksumPayloadOnly;
            _probeCompressedAuthResponseChecksumSeed = RetailCompressionCodec.NormalizeChecksumSeed(
                probeCompressedAuthResponseChecksumSeed,
                WorldGatewayProtocolConstants.TrinityCompressionAdlerSeed);
            _probeCompressedAuthResponseCompressedChecksumIncludeMetadata = probeCompressedAuthResponseCompressedChecksumIncludeMetadata;
            _probeRetailSequencePreludePayload = probeRetailSequencePreludePayload is { Length: 4 }
                ? probeRetailSequencePreludePayload.ToArray()
                : [0, 0, 0, 0];
            _authResponseFuzzMutation = authResponseFuzzMutation;
            _probeAuthResponseOpcode = probeAuthResponseOpcode == 0 ? WorldGatewayOpcodes.RetailSmsgAuthResponse : probeAuthResponseOpcode;
            _probeAuthResponseReplayPayload = probeAuthResponseReplayPayload is { Length: > 0 }
                ? probeAuthResponseReplayPayload.ToArray()
                : Array.Empty<byte>();
            _probeAuthResponseReplayCompressedPayload = probeAuthResponseReplayCompressedPayload is { Length: > 0 }
                ? probeAuthResponseReplayCompressedPayload.ToArray()
                : Array.Empty<byte>();
            _probeAuthResponseReplayPatchTimeToNow = probeAuthResponseReplayPatchTimeToNow;
            _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount = probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount;
            _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount = probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount;
            _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset = probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset;
            _probeAuthResponseReplayPatchCurrentBuildPresent = probeAuthResponseReplayPatchCurrentBuildPresent;
            _probeAuthResponseReplayPatchWaitInfoPresent = probeAuthResponseReplayPatchWaitInfoPresent;
            _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm = probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm;
            _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm = probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm;
            _probeAuthResponseReplayBisectionResultOnlyErrorOk = probeAuthResponseReplayBisectionResultOnlyErrorOk;
            _probeSetTimeZoneInformationPayload = probeSetTimeZoneInformationPayload is { Length: > 0 }
                ? probeSetTimeZoneInformationPayload.ToArray()
                : Array.Empty<byte>();
            _probeFeatureSystemStatusGlueScreenPayload = probeFeatureSystemStatusGlueScreenPayload is { Length: > 0 }
                ? probeFeatureSystemStatusGlueScreenPayload.ToArray()
                : Array.Empty<byte>();
            _probeMirrorVarsPayload = probeMirrorVarsPayload is { Length: > 0 }
                ? probeMirrorVarsPayload.ToArray()
                : Array.Empty<byte>();
            _probeCacheVersionPayload = probeCacheVersionPayload is { Length: > 0 }
                ? probeCacheVersionPayload.ToArray()
                : Array.Empty<byte>();
            _probeAvailableHotfixesPayload = probeAvailableHotfixesPayload is { Length: > 0 }
                ? probeAvailableHotfixesPayload.ToArray()
                : Array.Empty<byte>();
            _probeAccountDataTimesPayload = probeAccountDataTimesPayload is { Length: > 0 }
                ? probeAccountDataTimesPayload.ToArray()
                : Array.Empty<byte>();
            _probeTutorialFlagsPayload = probeTutorialFlagsPayload is { Length: > 0 }
                ? probeTutorialFlagsPayload.ToArray()
                : Array.Empty<byte>();
            _probeBattleNetConnectionStatusPayload = probeBattleNetConnectionStatusPayload is { Length: > 0 }
                ? probeBattleNetConnectionStatusPayload.ToArray()
                : Array.Empty<byte>();
            _acoreRealmId = acoreRealmId == 0 ? 1u : acoreRealmId;
            _controlledUnlockEmptyCharEnumEnabled = controlledUnlockEmptyCharEnumEnabled;
            _effectiveSuppressPostAuthBootstrapForProbe =
                suppressPostAuthBootstrapForProbe && !probeBareAuthResponseOnly;
            _forwardAcoreWardenAsRetailWarden3Data = forwardAcoreWardenAsRetailWarden3Data;
            _forwardAcoreAddonInfoAsRetailAddonListRequest = forwardAcoreAddonInfoAsRetailAddonListRequest;
            _forwardAcoreTutorialFlagsAsRetailTutorialFlags = forwardAcoreTutorialFlagsAsRetailTutorialFlags;
            _getEnterEncryptedModeFrame = getEnterEncryptedModeFrame;
            _onDeferredBootstrapPrepared = onDeferredBootstrapPrepared;
            _onEnterEncryptedModeSent = onEnterEncryptedModeSent;
            _onEnterEncryptedAwaitStart = onEnterEncryptedAwaitStart;
            _onBootstrapFlushedWithoutAck = onBootstrapFlushedWithoutAck;
            _onBootstrapSuppressedForProbe = onBootstrapSuppressedForProbe;
            _onCharEnumReceived = onCharEnumReceived;
            _onControlledUnlockApplied = onControlledUnlockApplied;
            _onFrameDecoded = onFrameDecoded;
            _onDroppedOpcode = onDroppedOpcode;
            _statefulCompressedAuthResponseCompressor =
                _probeCompressAuthResponseAsSmsgCompressedPacket &&
                _probeCompressedAuthResponseUseRawDeflate &&
                _probeCompressedAuthResponseUseStatefulDeflateSyncFlush
                    ? new StatefulRawDeflateSyncFlushCompressor(_probeCompressedAuthResponseRawDeflateLevel)
                    : null;
        }

        public bool TryTransform(ReadOnlySequence<byte> input, IBufferWriter<byte> output, out long bytesWritten, out string? error)
        {
            bytesWritten = 0;
            error = null;

            foreach (ReadOnlyMemory<byte> segment in input)
            {
                ReadOnlySpan<byte> span = segment.Span;
                for (int idx = 0; idx < span.Length; idx++)
                {
                    byte current = span[idx];

                    if (_payloadBytesExpected > 0)
                    {
                        _payloadBuffer[_payloadBytesRead++] = current;

                        if (_payloadBytesRead < _payloadBytesExpected)
                        {
                            continue;
                        }

                        if (!TryTranslateDecodedFrame(
                                _currentOpcode,
                                _payloadBuffer.AsSpan(0, _payloadBytesExpected),
                                output,
                                out long frameBytes,
                                out error))
                        {
                            return false;
                        }

                        bytesWritten += frameBytes;
                        ResetFrameState();
                        continue;
                    }

                    _header[_headerBytesRead] = current;
                    _authCrypt.TransformServerToClient(_header.AsSpan(_headerBytesRead, 1));
                    _headerBytesRead++;

                    if (_headerBytesRead == 1)
                    {
                        _headerBytesExpected = (_header[0] & 0x80) != 0 ? 5 : 4;
                    }

                    if (_headerBytesRead < _headerBytesExpected)
                    {
                        continue;
                    }

                    if (!PostAuthTranslationHelpers.TryDecodeAcoreServerPacketSize(_header.AsSpan(0, _headerBytesExpected), out int packetSizeIncludingOpcode, out string decodeError))
                    {
                        error = decodeError;
                        return false;
                    }

                    int payloadBytes = packetSizeIncludingOpcode - 2;
                    if (payloadBytes < 0 || payloadBytes > WorldGatewayProtocolConstants.AcorePostAuthServerMaxPacketBytes)
                    {
                        error = $"Invalid AC server payload size in header: {payloadBytes}.";
                        return false;
                    }

                    _currentOpcode = _headerBytesExpected == 4
                        ? BinaryPrimitives.ReadUInt16LittleEndian(_header.AsSpan(2, 2))
                        : BinaryPrimitives.ReadUInt16LittleEndian(_header.AsSpan(3, 2));
                    _payloadBytesExpected = payloadBytes;
                    _payloadBytesRead = 0;
                    _onFrameDecoded?.Invoke(_currentOpcode, _payloadBytesExpected);

                    if (_payloadBytesExpected == 0)
                    {
                        if (!TryTranslateDecodedFrame(_currentOpcode, ReadOnlySpan<byte>.Empty, output, out long frameBytes, out error))
                        {
                            return false;
                        }

                        bytesWritten += frameBytes;
                        ResetFrameState();
                        continue;
                    }

                    if (_payloadBuffer.Length < _payloadBytesExpected)
                    {
                        _payloadBuffer = GC.AllocateUninitializedArray<byte>(_payloadBytesExpected);
                    }
                }
            }

            return true;
        }

    }
}
