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

    }
}
