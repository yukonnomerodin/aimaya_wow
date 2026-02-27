using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private const int MaxServerPacketSize = 16 * 1024 * 1024;
        private const int MaxBufferedFramesBeforeAuth = 32;
        private const int MaxBufferedBytesBeforeAuth = 256 * 1024;

        private readonly AuthCrypt _authCrypt;
        private readonly WorldProxyBridgeState _bridgeState;
        private readonly bool _strictStageEnforcement;
        private readonly bool _waitForEnterEncryptedAckGate;
        private readonly bool _probeBareAuthResponseOnly;
        private readonly bool _probeAuthResponseResultOnly;
        private readonly uint _probeAuthResponseResultOnlyCode;
        private readonly bool _probeAuthResponseMinimalSuccessNoAccountData;
        private readonly bool _probeAuthResponseTwwAccountDataProfile;
        private readonly bool _probeAuthResponseTwwAddResultPrefix;
        private readonly bool _probeAuthResponseForceWaitInfoPresent;
        private readonly bool _probeAuthResponseForceCurrentBuildPresent;
        private readonly int _probeAuthResponseAvailableClassesCardinality;
        private readonly int _probeAuthResponseTwwClassMatrixRows;
        private readonly bool _probeAuthResponseTwwUseAcoreExpansionLevels;
        private readonly bool _probeInsertRetailSequencePreludeBeforeAuthResponse;
        private readonly bool _probeInsertRetailSequencePreludeAfterAuthResponse;
        private readonly bool _probeReorderFirstDeferredFrameAfterPrelude;
        private readonly bool _probeFeatureSystemStatusGlueScreenTrinitySemantics;
        private readonly bool _probeCompressAuthResponseAsSmsgCompressedPacket;
        private readonly bool _probeCompressedAuthResponseForceEnvelope;
        private readonly bool _probeCompressedAuthResponseUseRawDeflate;
        private readonly bool _probeCompressedAuthResponseUseStatefulDeflateSyncFlush;
        private readonly int _probeCompressedAuthResponseRawDeflateLevel;
        private readonly bool _probeCompressedAuthResponseChecksumPayloadOnly;
        private readonly uint _probeCompressedAuthResponseChecksumSeed;
        private readonly bool _probeCompressedAuthResponseCompressedChecksumIncludeMetadata;
        private readonly byte[] _probeRetailSequencePreludePayload;
        private readonly AuthResponseFuzzMutation _authResponseFuzzMutation;
        private readonly uint _probeAuthResponseOpcode;
        private readonly byte[] _probeAuthResponseReplayPayload;
        private readonly byte[] _probeAuthResponseReplayCompressedPayload;
        private readonly bool _probeAuthResponseReplayPatchTimeToNow;
        private readonly bool _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount;
        private readonly bool _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount;
        private readonly bool _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset;
        private readonly bool _probeAuthResponseReplayPatchCurrentBuildPresent;
        private readonly bool _probeAuthResponseReplayPatchWaitInfoPresent;
        private readonly bool _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm;
        private readonly bool _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm;
        private readonly bool _probeAuthResponseReplayBisectionResultOnlyErrorOk;
        private readonly byte[] _probeSetTimeZoneInformationPayload;
        private readonly byte[] _probeFeatureSystemStatusGlueScreenPayload;
        private readonly byte[] _probeMirrorVarsPayload;
        private readonly byte[] _probeCacheVersionPayload;
        private readonly byte[] _probeAvailableHotfixesPayload;
        private readonly byte[] _probeAccountDataTimesPayload;
        private readonly byte[] _probeTutorialFlagsPayload;
        private readonly byte[] _probeBattleNetConnectionStatusPayload;
        private readonly uint _acoreRealmId;
        private readonly bool _controlledUnlockEmptyCharEnumEnabled;
        private readonly bool _effectiveSuppressPostAuthBootstrapForProbe;
        private readonly bool _forwardAcoreWardenAsRetailWarden3Data;
        private readonly bool _forwardAcoreAddonInfoAsRetailAddonListRequest;
        private readonly bool _forwardAcoreTutorialFlagsAsRetailTutorialFlags;
        private readonly Func<byte[]?>? _getEnterEncryptedModeFrame;
        private readonly Action<byte[], string>? _onDeferredBootstrapPrepared;
        private readonly Action? _onEnterEncryptedModeSent;
        private readonly Action<string>? _onEnterEncryptedAwaitStart;
        private readonly Action<int, string>? _onBootstrapFlushedWithoutAck;
        private readonly Action<int, string>? _onBootstrapSuppressedForProbe;
        private readonly Action? _onCharEnumReceived;
        private readonly Action<int, int>? _onControlledUnlockApplied;
        private readonly Action<ushort, int>? _onFrameDecoded;
        private readonly Action<ushort, int>? _onDroppedOpcode;
        private readonly HashSet<ushort> _loggedDroppedOpcodes = new();
        private readonly StatefulRawDeflateSyncFlushCompressor? _statefulCompressedAuthResponseCompressor;
        private readonly byte[] _header = new byte[5];
        private readonly List<BufferedServerFrame> _bufferedBeforeAuth = new();
        private bool _authResponseForwarded;
        private int _bufferedBeforeAuthBytes;

        private int _headerBytesRead;
        private int _headerBytesExpected;
        private ushort _currentOpcode;
        private int _payloadBytesExpected;
        private int _payloadBytesRead;
        private byte[] _payloadBuffer = Array.Empty<byte>();

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
            long probeCompressedAuthResponseChecksumSeed = TrinityCompressionAdlerSeed,
            bool probeCompressedAuthResponseCompressedChecksumIncludeMetadata = false,
            byte[]? probeRetailSequencePreludePayload = null,
            AuthResponseFuzzMutation authResponseFuzzMutation = default,
            uint probeAuthResponseOpcode = RetailOpcodeSmsgAuthResponse,
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
            _probeCompressedAuthResponseChecksumSeed = RetailCompressionCodec.NormalizeChecksumSeed(probeCompressedAuthResponseChecksumSeed, TrinityCompressionAdlerSeed);
            _probeCompressedAuthResponseCompressedChecksumIncludeMetadata = probeCompressedAuthResponseCompressedChecksumIncludeMetadata;
            _probeRetailSequencePreludePayload = probeRetailSequencePreludePayload is { Length: 4 }
                ? probeRetailSequencePreludePayload.ToArray()
                : [0, 0, 0, 0];
            _authResponseFuzzMutation = authResponseFuzzMutation;
            _probeAuthResponseOpcode = probeAuthResponseOpcode == 0 ? RetailOpcodeSmsgAuthResponse : probeAuthResponseOpcode;
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
                    if (payloadBytes < 0 || payloadBytes > MaxServerPacketSize)
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
                    if (_bufferedBeforeAuth.Count >= MaxBufferedFramesBeforeAuth ||
                        _bufferedBeforeAuthBytes + payload.Length > MaxBufferedBytesBeforeAuth)
                    {
                        if (_loggedDroppedOpcodes.Add(opcode))
                        {
                            _onDroppedOpcode?.Invoke(opcode, payload.Length);
                        }

                        return true;
                    }

                    byte[] payloadCopy = GC.AllocateUninitializedArray<byte>(payload.Length);
                    payload.CopyTo(payloadCopy);
                    _bufferedBeforeAuth.Add(new BufferedServerFrame(opcode, payloadCopy));
                    _bufferedBeforeAuthBytes += payload.Length;
                    return true;
                }

                byte[] mapped;
                bool authResponseAlreadyCompressed = false;
                if (_probeAuthResponseReplayPayload.Length > 0)
                {
                    if (_probeAuthResponseReplayBisectionResultOnlyErrorOk)
                    {
                        Span<byte> resultOnlyPayload = stackalloc byte[sizeof(uint)];
                        BinaryPrimitives.WriteUInt32LittleEndian(resultOnlyPayload, 0u); // ERROR_OK
                        mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(_probeAuthResponseOpcode, resultOnlyPayload);
                    }
                    else
                    {
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
                    }
                }
                else if (!AuthResponseFrameBuilder.TryBuildRetailAuthResponseFromAcore(
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
                             out error))
                {
                    return false;
                }

                if (_probeCompressAuthResponseAsSmsgCompressedPacket && !authResponseAlreadyCompressed)
                {
                    if (!RetailCompressedPacketWrapper.TryBuildRetailCompressedPacketFrame(
                            mapped,
                            _probeCompressedAuthResponseForceEnvelope,
                            _probeCompressedAuthResponseUseRawDeflate,
                            _probeCompressedAuthResponseUseStatefulDeflateSyncFlush,
                            _probeCompressedAuthResponseRawDeflateLevel,
                            _probeCompressedAuthResponseChecksumPayloadOnly,
                            _probeCompressedAuthResponseChecksumSeed,
                            _probeCompressedAuthResponseCompressedChecksumIncludeMetadata,
                            _statefulCompressedAuthResponseCompressor,
                            RetailOpcodeSmsgCompressedPacket,
                            TrinityCompressionThresholdBytes,
                            out byte[] compressedAuthResponse,
                            out string? compressionError))
                    {
                        error = $"Failed to wrap AUTH_RESPONSE as SMSG_COMPRESSED_PACKET: {compressionError ?? "<unknown>"}";
                        return false;
                    }

                    mapped = compressedAuthResponse;
                }

                var bootstrapBuffer = new ArrayBufferWriter<byte>(1024);
                var stagedOpcodes = new List<string>(16);

                if (_probeInsertRetailSequencePreludeBeforeAuthResponse)
                {
                    byte[] prelude = RetailAuthSequencePreludeBuilder.BuildFrame(RetailOpcodeSmsgAuthSequencePrelude, _probeRetailSequencePreludePayload);
                    bootstrapBuffer.Write(prelude);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAuthSequencePrelude:X8}");
                }

                bootstrapBuffer.Write(mapped);
                uint stagedAuthOpcode = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(16, 4));
                stagedOpcodes.Add($"0x{stagedAuthOpcode:X8}");

                if (_probeInsertRetailSequencePreludeAfterAuthResponse)
                {
                    byte[] prelude = RetailAuthSequencePreludeBuilder.BuildFrame(RetailOpcodeSmsgAuthSequencePrelude, _probeRetailSequencePreludePayload);
                    bootstrapBuffer.Write(prelude);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAuthSequencePrelude:X8}");
                }

                if (!_probeBareAuthResponseOnly)
                {
                    // Trinity-authenticated bootstrap parity:
                    // AUTH_RESPONSE -> TIME_ZONE -> FEATURE -> MIRROR_VARS ->
                    // CACHE_VERSION -> AVAILABLE_HOTFIXES -> ACCOUNT_DATA_TIMES ->
                    // TUTORIAL_FLAGS -> BATTLE_NET_CONNECTION_STATUS.
                    byte[]? cacheVersionPayload = null;
                    byte[]? tutorialFlagsPayload = null;

                    for (int i = 0; i < _bufferedBeforeAuth.Count; i++)
                    {
                        BufferedServerFrame buffered = _bufferedBeforeAuth[i];
                        switch (buffered.Opcode)
                        {
                            case AcoreOpcodeSmsgClientCacheVersion when cacheVersionPayload is null:
                                cacheVersionPayload = buffered.Payload;
                                break;
                            case AcoreOpcodeSmsgTutorialFlags
                                when _forwardAcoreTutorialFlagsAsRetailTutorialFlags &&
                                     tutorialFlagsPayload is null &&
                                     buffered.Payload.Length == RetailTutorialValuesCount * sizeof(uint):
                                tutorialFlagsPayload = buffered.Payload;
                                break;
                            default:
                                if (_loggedDroppedOpcodes.Add(buffered.Opcode))
                                {
                                    _onDroppedOpcode?.Invoke(buffered.Opcode, buffered.Payload.Length);
                                }

                                break;
                        }
                    }

                    byte[] timezone = _probeSetTimeZoneInformationPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgSetTimeZoneInformation, _probeSetTimeZoneInformationPayload)
                        : RetailSetTimeZoneInformationBuilder.BuildFrame(RetailOpcodeSmsgSetTimeZoneInformation);
                    bootstrapBuffer.Write(timezone);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgSetTimeZoneInformation:X8}");

                    byte[] features = _probeFeatureSystemStatusGlueScreenPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgFeatureSystemStatusGlueScreen, _probeFeatureSystemStatusGlueScreenPayload)
                        : RetailFeatureSystemStatusGlueScreenBuilder.BuildFrame(
                            RetailOpcodeSmsgFeatureSystemStatusGlueScreen,
                            _probeFeatureSystemStatusGlueScreenTrinitySemantics);
                    bootstrapBuffer.Write(features);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgFeatureSystemStatusGlueScreen:X8}");

                    byte[] mirrorVars = _probeMirrorVarsPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgMirrorVars, _probeMirrorVarsPayload)
                        : RetailGluePayloadBuilders.BuildMirrorVarsFrame(RetailOpcodeSmsgMirrorVars);
                    bootstrapBuffer.Write(mirrorVars);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgMirrorVars:X8}");

                    byte[] cacheVersion = _probeCacheVersionPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgCacheVersion, _probeCacheVersionPayload)
                        : RetailGluePayloadBuilders.BuildCacheVersionFrame(RetailOpcodeSmsgCacheVersion, cacheVersionPayload);
                    bootstrapBuffer.Write(cacheVersion);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgCacheVersion:X8}");

                    byte[] availableHotfixes = _probeAvailableHotfixesPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAvailableHotfixes, _probeAvailableHotfixesPayload)
                        : RetailGluePayloadBuilders.BuildAvailableHotfixesFrame(RetailOpcodeSmsgAvailableHotfixes, _acoreRealmId);
                    bootstrapBuffer.Write(availableHotfixes);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAvailableHotfixes:X8}");

                    byte[] accountDataTimes = _probeAccountDataTimesPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAccountDataTimes, _probeAccountDataTimesPayload)
                        : RetailGluePayloadBuilders.BuildAccountDataTimesFrame(RetailOpcodeSmsgAccountDataTimes, RetailAccountDataTimesCount);
                    bootstrapBuffer.Write(accountDataTimes);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAccountDataTimes:X8}");

                    byte[] tutorialFlags = _probeTutorialFlagsPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTutorialFlags, _probeTutorialFlagsPayload)
                        : RetailGluePayloadBuilders.BuildTutorialFlagsFrame(
                            RetailOpcodeSmsgTutorialFlags,
                            tutorialFlagsPayload,
                            RetailTutorialValuesCount * sizeof(uint));
                    bootstrapBuffer.Write(tutorialFlags);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgTutorialFlags:X8}");

                    byte[] battleNetConnectionStatus = _probeBattleNetConnectionStatusPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgBattleNetConnectionStatus, _probeBattleNetConnectionStatusPayload)
                        : RetailGluePayloadBuilders.BuildBattleNetConnectionStatusFrame(
                            RetailOpcodeSmsgBattleNetConnectionStatus,
                            state: 1,
                            suppressNotification: true);
                    bootstrapBuffer.Write(battleNetConnectionStatus);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgBattleNetConnectionStatus:X8}");
                }
                else
                {
                    for (int i = 0; i < _bufferedBeforeAuth.Count; i++)
                    {
                        BufferedServerFrame buffered = _bufferedBeforeAuth[i];
                        if (_loggedDroppedOpcodes.Add(buffered.Opcode))
                        {
                            _onDroppedOpcode?.Invoke(buffered.Opcode, buffered.Payload.Length);
                        }
                    }
                }

                if (_probeReorderFirstDeferredFrameAfterPrelude)
                {
                    PostAuthTranslationHelpers.ReorderFirstDeferredFrameAfterPrelude(
                        bootstrapBuffer,
                        stagedOpcodes,
                        RetailOpcodeSmsgAuthSequencePrelude);
                }

                byte[] bootstrapPayload = bootstrapBuffer.WrittenMemory.ToArray();
                string stagedOpcodeList = stagedOpcodes.Count > 0
                    ? string.Join(", ", stagedOpcodes)
                    : "<none>";

                byte[]? enterEncryptedModeFrame = _getEnterEncryptedModeFrame?.Invoke();
                if (enterEncryptedModeFrame is { Length: > 0 })
                {
                    if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, enterEncryptedModeFrame, output, out long enterEncryptedBytes, out error))
                    {
                        return false;
                    }

                    bytesWritten += enterEncryptedBytes;
                    _onEnterEncryptedModeSent?.Invoke();

                    if (_waitForEnterEncryptedAckGate)
                    {
                        _onDeferredBootstrapPrepared?.Invoke(bootstrapPayload, stagedOpcodeList);
                        _onEnterEncryptedAwaitStart?.Invoke(stagedOpcodeList);
                    }
                    else
                    {
                        if (_effectiveSuppressPostAuthBootstrapForProbe)
                        {
                            _onBootstrapSuppressedForProbe?.Invoke(bootstrapPayload.Length, stagedOpcodeList);
                        }
                        else
                        {
                            // Trinity-like behavior: do not block post-auth bootstrap on plaintext ACK.
                            if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrameBatch(_bridgeState, bootstrapPayload, output, out long bootstrapBytes, out error))
                            {
                                return false;
                            }

                            bytesWritten += bootstrapBytes;
                            _onBootstrapFlushedWithoutAck?.Invoke(bootstrapPayload.Length, stagedOpcodeList);
                        }
                    }
                }
                else
                {
                    if (_effectiveSuppressPostAuthBootstrapForProbe)
                    {
                        _onBootstrapSuppressedForProbe?.Invoke(bootstrapPayload.Length, stagedOpcodeList);
                    }
                    else
                    {
                        if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrameBatch(_bridgeState, bootstrapPayload, output, out long bootstrapBytes, out error))
                        {
                            return false;
                        }

                        bytesWritten += bootstrapBytes;
                    }
                }

                _authResponseForwarded = true;
                _bufferedBeforeAuth.Clear();
                _bufferedBeforeAuthBytes = 0;
                return true;
            }

            return TryTranslateAfterAuth(opcode, payload, output, out bytesWritten, out error);
        }

        private void ResetFrameState()
        {
            _headerBytesRead = 0;
            _headerBytesExpected = 0;
            _currentOpcode = 0;
            _payloadBytesExpected = 0;
            _payloadBytesRead = 0;
        }

        private readonly record struct BufferedServerFrame(ushort Opcode, byte[] Payload);
    }
}
