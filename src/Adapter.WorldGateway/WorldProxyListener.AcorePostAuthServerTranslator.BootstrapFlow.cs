using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryStageAndFlushAuthBootstrap(byte[] mapped, IBufferWriter<byte> output, ref long bytesWritten, out string? error)
        {
            var bootstrapBuffer = new ArrayBufferWriter<byte>(1024);
            var stagedOpcodes = new List<string>(16);

            if (_probeInsertRetailSequencePreludeBeforeAuthResponse)
            {
                byte[] prelude = RetailAuthSequencePreludeBuilder.BuildFrame(WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude, _probeRetailSequencePreludePayload);
                bootstrapBuffer.Write(prelude);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude:X8}");
            }

            bootstrapBuffer.Write(mapped);
            uint stagedAuthOpcode = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(16, 4));
            stagedOpcodes.Add($"0x{stagedAuthOpcode:X8}");

            if (_probeInsertRetailSequencePreludeAfterAuthResponse)
            {
                byte[] prelude = RetailAuthSequencePreludeBuilder.BuildFrame(WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude, _probeRetailSequencePreludePayload);
                bootstrapBuffer.Write(prelude);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude:X8}");
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
                        case WorldGatewayOpcodes.AcoreSmsgClientCacheVersion when cacheVersionPayload is null:
                            cacheVersionPayload = buffered.Payload;
                            break;
                        case WorldGatewayOpcodes.AcoreSmsgTutorialFlags
                            when _forwardAcoreTutorialFlagsAsRetailTutorialFlags &&
                                 tutorialFlagsPayload is null &&
                                 buffered.Payload.Length == WorldGatewayProtocolConstants.RetailTutorialValuesCount * sizeof(uint):
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
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgSetTimeZoneInformation, _probeSetTimeZoneInformationPayload)
                    : RetailSetTimeZoneInformationBuilder.BuildFrame(WorldGatewayOpcodes.RetailSmsgSetTimeZoneInformation);
                bootstrapBuffer.Write(timezone);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgSetTimeZoneInformation:X8}");

                byte[] features = _probeFeatureSystemStatusGlueScreenPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgFeatureSystemStatusGlueScreen, _probeFeatureSystemStatusGlueScreenPayload)
                    : RetailFeatureSystemStatusGlueScreenBuilder.BuildFrame(
                        WorldGatewayOpcodes.RetailSmsgFeatureSystemStatusGlueScreen,
                        _probeFeatureSystemStatusGlueScreenTrinitySemantics);
                bootstrapBuffer.Write(features);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgFeatureSystemStatusGlueScreen:X8}");

                byte[] mirrorVars = _probeMirrorVarsPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgMirrorVars, _probeMirrorVarsPayload)
                    : RetailGluePayloadBuilders.BuildMirrorVarsFrame(WorldGatewayOpcodes.RetailSmsgMirrorVars);
                bootstrapBuffer.Write(mirrorVars);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgMirrorVars:X8}");

                byte[] cacheVersion = _probeCacheVersionPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgCacheVersion, _probeCacheVersionPayload)
                    : RetailGluePayloadBuilders.BuildCacheVersionFrame(WorldGatewayOpcodes.RetailSmsgCacheVersion, cacheVersionPayload);
                bootstrapBuffer.Write(cacheVersion);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgCacheVersion:X8}");

                byte[] availableHotfixes = _probeAvailableHotfixesPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgAvailableHotfixes, _probeAvailableHotfixesPayload)
                    : RetailGluePayloadBuilders.BuildAvailableHotfixesFrame(WorldGatewayOpcodes.RetailSmsgAvailableHotfixes, _acoreRealmId);
                bootstrapBuffer.Write(availableHotfixes);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgAvailableHotfixes:X8}");

                byte[] accountDataTimes = _probeAccountDataTimesPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgAccountDataTimes, _probeAccountDataTimesPayload)
                    : RetailGluePayloadBuilders.BuildAccountDataTimesFrame(
                        WorldGatewayOpcodes.RetailSmsgAccountDataTimes,
                        WorldGatewayProtocolConstants.RetailAccountDataTimesCount);
                bootstrapBuffer.Write(accountDataTimes);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgAccountDataTimes:X8}");

                byte[] tutorialFlags = _probeTutorialFlagsPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgTutorialFlags, _probeTutorialFlagsPayload)
                    : RetailGluePayloadBuilders.BuildTutorialFlagsFrame(
                        WorldGatewayOpcodes.RetailSmsgTutorialFlags,
                        tutorialFlagsPayload,
                        WorldGatewayProtocolConstants.RetailTutorialValuesCount * sizeof(uint));
                bootstrapBuffer.Write(tutorialFlags);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgTutorialFlags:X8}");

                byte[] battleNetConnectionStatus = _probeBattleNetConnectionStatusPayload.Length > 0
                    ? RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgBattleNetConnectionStatus, _probeBattleNetConnectionStatusPayload)
                    : RetailGluePayloadBuilders.BuildBattleNetConnectionStatusFrame(
                        WorldGatewayOpcodes.RetailSmsgBattleNetConnectionStatus,
                        state: 1,
                        suppressNotification: true);
                bootstrapBuffer.Write(battleNetConnectionStatus);
                stagedOpcodes.Add($"0x{WorldGatewayOpcodes.RetailSmsgBattleNetConnectionStatus:X8}");
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
                    WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude);
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
            error = null;
            return true;
        }
    }
}
