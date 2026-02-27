using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using MySqlConnector;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async Task HandleConnectionAsync(TcpClient downstreamClient, uint connectionId, CancellationToken serverToken)
    {
        using (downstreamClient)
        {
            string downstreamRemote = downstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            string downstreamKey = WorldProxyRuntimeHelpers.ResolveDownstreamKey(downstreamClient.Client.RemoteEndPoint, downstreamRemote);
            downstreamClient.NoDelay = true;
            DateTimeOffset connectionOpenedAt = DateTimeOffset.UtcNow;

            _logger.LogInformation(
                "World connection opened: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}",
                connectionId,
                downstreamRemote);

            if (ReconnectCooldownHelpers.TryGetRemainingMs(
                    _reconnectCooldownUntilByKey,
                    _options.ReconnectCooldownMs,
                    downstreamKey,
                    out int reconnectCooldownRemainingMs))
            {
                _logger.LogInformation(
                    "[WorldProxy][ANTISPAM] Reconnect blocked by cooldown. ConnectionId={ConnectionId}, DownstreamKey={DownstreamKey}, RemainingMs={RemainingMs}, CooldownMs={CooldownMs}",
                    connectionId,
                    downstreamKey,
                    reconnectCooldownRemainingMs,
                    _options.ReconnectCooldownMs);
                return;
            }

            using var upstreamClient = new TcpClient(AddressFamily.InterNetwork);
            upstreamClient.NoDelay = true;

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                connectCts.CancelAfter(_options.UpstreamConnectTimeoutMs);
                await upstreamClient.ConnectAsync(_options.UpstreamAddress, _options.UpstreamPort, connectCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException)
            {
                _logger.LogWarning(
                    ex,
                    "Upstream connect failed: ConnectionId={ConnectionId}, Upstream={UpstreamAddress}:{UpstreamPort}",
                    connectionId,
                    _options.UpstreamAddress,
                    _options.UpstreamPort);
                return;
            }

            string upstreamRemote = upstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            _logger.LogInformation(
                "World upstream connected: ConnectionId={ConnectionId}, Upstream={UpstreamRemote}",
                connectionId,
                upstreamRemote);

            await using NetworkStream downstreamStream = downstreamClient.GetStream();
            await using NetworkStream upstreamStream = upstreamClient.GetStream();

            if (_options.EnableRetailConnectionInitializer)
            {
                bool initialized = await TryPerformRetailConnectionInitializerAsync(connectionId, downstreamStream, relayToken: serverToken).ConfigureAwait(false);
                if (!initialized)
                {
                    _logger.LogWarning(
                        "World initializer failed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}. Closing connection.",
                        connectionId,
                        downstreamRemote);
                    return;
                }
            }

            var downstreamReader = PipeReader.Create(
                downstreamStream,
                new StreamPipeReaderOptions(
                    bufferSize: _options.ReaderBufferSize,
                    minimumReadSize: _options.MinimumReadSize,
                    leaveOpen: true));

            var downstreamWriter = PipeWriter.Create(downstreamStream, new StreamPipeWriterOptions(leaveOpen: true));
            var upstreamReader = PipeReader.Create(
                upstreamStream,
                new StreamPipeReaderOptions(
                    bufferSize: _options.ReaderBufferSize,
                    minimumReadSize: _options.MinimumReadSize,
                    leaveOpen: true));

            var upstreamWriter = PipeWriter.Create(upstreamStream, new StreamPipeWriterOptions(leaveOpen: true));

            using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
            var bridgeState = new WorldProxyBridgeState(
                logger: _logger,
                retailWorldPacketCryptServerInitialCounter: (ulong)_options.RetailWorldPacketCryptServerInitialCounter,
                retailWorldPacketCryptUseSizeAsAad: _options.RetailWorldPacketCryptUseSizeAsAad,
                retailWorldPacketCryptAadSizeBytes: _options.RetailWorldPacketCryptAadSizeBytes,
                retailWorldPacketCryptUseEmptyAad: _options.RetailWorldPacketCryptUseEmptyAad,
                retailWorldPacketCryptNonceLayout: _options.RetailWorldPacketCryptNonceLayout,
                retailWorldPacketCryptServerNonceMagic: _options.RetailWorldPacketCryptServerNonceMagic,
                retailWorldPacketCryptClientNonceMagic: _options.RetailWorldPacketCryptClientNonceMagic);
            bridgeState.SetConnectionOpenedAt(connectionOpenedAt);
            bridgeState.SetBaseline(
                new HandshakeBaseline(
                    ScenarioId: _protocolOptions.ScenarioId,
                    ClientBuild: _protocolOptions.ClientBuild,
                    RealmConfig: _protocolOptions.RealmConfig,
                    AccountIdentity: _protocolOptions.AccountIdentity,
                    AckPolicy: _protocolOptions.AckPolicy,
                    PassThreshold: _protocolOptions.PassThreshold,
                    DeterministicReplayEnabled: _protocolOptions.DeterministicReplayEnabled,
                    FailureClassTarget: _protocolOptions.FailureClassTarget,
                    ActiveLayer: _protocolOptions.ActiveLayer,
                    ParityAxis: _protocolOptions.ParityAxis,
                    BaselineTimestampUtc: DateTimeOffset.UtcNow.ToString("O")));

            Task<long> downstreamToUpstream = ProxyStreamAsync(
                connectionId,
                "client->world",
                downstreamReader,
                upstreamWriter,
                downstreamKey,
                bridgeState,
                relayCts.Token);

            Task<long> upstreamToDownstream = ProxyStreamAsync(
                connectionId,
                "world->client",
                upstreamReader,
                downstreamWriter,
                downstreamKey,
                bridgeState,
                relayCts.Token);

            long transferredClientToWorld = 0;
            long transferredWorldToClient = 0;

            try
            {
                Task completed = await Task.WhenAny(downstreamToUpstream, upstreamToDownstream).ConfigureAwait(false);
                string firstCompletedDirection = ReferenceEquals(completed, downstreamToUpstream)
                    ? "client->world"
                    : "world->client";
                string firstCompletedStatus = completed.IsFaulted
                    ? "faulted"
                    : completed.IsCanceled
                        ? "canceled"
                        : "completed";
                string firstCompletedError = completed.Exception?.GetBaseException().Message ?? "<none>";
                _logger.LogInformation(
                    "[WorldProxy][L4] First relay side finished. ConnectionId={ConnectionId}, Direction={Direction}, Status={Status}, Error={Error}",
                    connectionId,
                    firstCompletedDirection,
                    firstCompletedStatus,
                    firstCompletedError);
                relayCts.Cancel();

                try
                {
                    await completed.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected when one side closes first.
                }

                try
                {
                    transferredClientToWorld = await downstreamToUpstream.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ignore cancellation, this is normal on half-close.
                }

                try
                {
                    transferredWorldToClient = await upstreamToDownstream.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ignore cancellation, this is normal on half-close.
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Proxy loop error: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}",
                    connectionId,
                    downstreamRemote,
                    upstreamRemote);
            }
            finally
            {
                await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(downstreamReader).ConfigureAwait(false);
                await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(downstreamWriter).ConfigureAwait(false);
                await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(upstreamReader).ConfigureAwait(false);
                await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(upstreamWriter).ConfigureAwait(false);
            }

            _logger.LogInformation(
                "World connection closed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}, BytesClientToWorld={BytesClientToWorld}, BytesWorldToClient={BytesWorldToClient}",
                connectionId,
                downstreamRemote,
                upstreamRemote,
                transferredClientToWorld,
                transferredWorldToClient);

            if (_options.EnableHandshakeLabReport)
            {
                try
                {
                    HandshakeLabReport report = HandshakeLabReport.Create(
                        connectionId,
                        _options,
                        _protocolOptions,
                        bridgeState,
                        connectionOpenedAt,
                        DateTimeOffset.UtcNow,
                        transferredClientToWorld,
                        transferredWorldToClient);

                    string reportPath = HandshakeDiagnosticsWriters.WriteHandshakeLabReport(
                        report,
                        WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options));
                    HandshakeDiagnosticsWriters.AppendNegativeEvidenceMatrixRow(
                        reportPath,
                        report,
                        WorldGatewayPathResolver.ResolveProofPackRoot(_options));
                    _logger.LogInformation(
                        "[WorldProxy][HANDSHAKE-LAB] Report written. ConnectionId={ConnectionId}, Path={Path}",
                        connectionId,
                        reportPath);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                {
                    _logger.LogWarning(
                        ex,
                        "[WorldProxy][HANDSHAKE-LAB] Failed to write report. ConnectionId={ConnectionId}",
                        connectionId);
                }
            }
        }
    }

    private void ValidateProtocolExperimentContractOrThrow()
    {
        if (string.IsNullOrWhiteSpace(_protocolOptions.HypothesisId) ||
            string.IsNullOrWhiteSpace(_protocolOptions.SingleChangedVariable) ||
            string.IsNullOrWhiteSpace(_protocolOptions.ExpectedObservable) ||
            string.IsNullOrWhiteSpace(_protocolOptions.NextIsolationVariable))
        {
            throw new InvalidOperationException(
                "ProtocolEngineering experiment contract is incomplete. Set HypothesisId, SingleChangedVariable, ExpectedObservable, and NextIsolationVariable before running.");
        }

        string matrixPath = Path.Combine(WorldGatewayPathResolver.ResolveProofPackRoot(_options), "matrix", "negative_evidence.csv");
        if (!File.Exists(matrixPath))
        {
            return;
        }

        if (MatrixPolicyGuard.TryFindRejectedChangeSet(matrixPath, _protocolOptions.SingleChangedVariable, out string? rejectedHypothesis))
        {
            throw new InvalidOperationException(
                $"Rejected change set replay is blocked by matrix policy. SingleChangedVariable='{_protocolOptions.SingleChangedVariable}', RejectedHypothesis='{rejectedHypothesis ?? "<unknown>"}', Matrix='{matrixPath}'.");
        }
    }

    private async Task<long> ProxyStreamAsync(
        uint connectionId,
        string direction,
        PipeReader reader,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        bool firstChunkDumped = false;
        bool firstAcoreChallengeBridged = false;
        bool firstRetailAuthSessionBridged = false;
        bool firstPostAuthDumpedClient = false;
        bool firstPostAuthDumpedServer = false;
        int acServerFramesLogged = 0;
        RetailPostAuthClientTranslator? retailPostAuthClientTranslator = null;
        AcorePostAuthServerTranslator? acorePostAuthServerTranslator = null;
        bool waitForEnterEncryptedAckGate = AckPolicyResolver.ResolveEffectiveWaitForAckGate(
            _ackPolicyMode,
            _options.EnterEncryptedModeAckGateEnabled,
            _protocolOptions.AckPolicy,
            _protocolOptions.AckPolicyDecisionPath,
            out _);

        while (!cancellationToken.IsCancellationRequested)
        {
            ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = readResult.Buffer;

            if (!buffer.IsEmpty)
            {
                if (_options.EnableFirstPacketDump && !firstChunkDumped)
                {
                    firstChunkDumped = true;
                    int maxBytes = _options.FirstPacketDumpBytes <= 0 ? DefaultDumpBytes : _options.FirstPacketDumpBytes;
                    _logger.LogInformation(
                        "[WorldProxy][DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, maxBytes));

                    if (RetailFrameCodec.TryDecodeFirstHeader(buffer, out DumpHeaderDecode decode))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][DUMP-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, FrameBytes={FrameBytes}, SizeBE={SizeBE}, SizeLE={SizeLE}, OpcodeLE=0x{OpcodeLE:X4}, OpcodeBE=0x{OpcodeBE:X4}, SizeBEMatches={SizeBEMatches}",
                            connectionId,
                            direction,
                            buffer.Length,
                            decode.SizeBE,
                            decode.SizeLE,
                            decode.OpcodeLE,
                            decode.OpcodeBE,
                            decode.SizeBEMatches);

                        if (direction == "world->client" &&
                            decode.OpcodeLE == AcoreOpcodeAuthChallenge &&
                            AcoreAuthChallengeDumpDecoder.TryDecode(buffer, out AcoreAuthChallengeDump challenge))
                        {
                            bridgeState.SetAcoreAuthSeed(challenge.AuthSeed);
                            bridgeState.SetAcoreServerChallenge(challenge.NewSeed);

                            _logger.LogInformation(
                                "[WorldProxy][DUMP-AC-AUTH-CHALLENGE] ConnectionId={ConnectionId}, DosChallenge={DosChallenge}, AuthSeed=0x{AuthSeed:X8}, NewSeed={NewSeedHex}",
                                connectionId,
                                challenge.DosChallenge,
                                challenge.AuthSeed,
                                challenge.NewSeedHex);
                        }
                    }
                }

                if (direction == "client->world" &&
                    retailPostAuthClientTranslator is null &&
                    bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt sendCrypt))
                {
                    retailPostAuthClientTranslator = new RetailPostAuthClientTranslator(
                        sendCrypt,
                        bridgeState,
                        strictStageEnforcement: _protocolOptions.StrictStageEnforcement,
                        onLogDisconnect: reason =>
                        {
                            bridgeState.SetLogDisconnectReason(reason);
                            if (ReconnectCooldownHelpers.TryArm(
                                    _reconnectCooldownUntilByKey,
                                    _options.ReconnectCooldownMs,
                                    downstreamKey,
                                    out long cooldownUntilUnixMs))
                            {
                                _logger.LogInformation(
                                    "[WorldProxy][ANTISPAM] Reconnect cooldown armed. DownstreamKey={DownstreamKey}, CooldownMs={CooldownMs}, Source={Source}, Reason={Reason}, UntilUnixMs={UntilUnixMs}",
                                    downstreamKey,
                                    _options.ReconnectCooldownMs,
                                    "cmsg_log_disconnect",
                                    reason.ToString(CultureInfo.InvariantCulture),
                                    cooldownUntilUnixMs);
                            }

                            bridgeState.MarkClientRequestedDisconnect();
                            _logger.LogInformation(
                                "[WorldProxy][MAP] Retail CMSG_LOG_DISCONNECT received. ConnectionId={ConnectionId}, Reason={Reason}",
                                connectionId,
                                reason);
                        },
                        onEnumCharactersRequest: () =>
                        {
                            if (!bridgeState.TryTransitionStage(
                                    BridgeStage.CHAR_ENUM_REQUESTED,
                                    "Retail CMSG_ENUM_CHARACTERS forwarded."))
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][STATE] CHAR_ENUM_REQUESTED transition rejected. ConnectionId={ConnectionId}, Stage={Stage}",
                                    connectionId,
                                    bridgeState.CurrentStage);
                            }
                        },
                        onEnterEncryptedModeAck: () =>
                        {
                            bool signaled = bridgeState.SignalEnterEncryptedAck();
                            bridgeState.MarkEnterEncryptedAckObserved();
                            if (bridgeState.CurrentStage < BridgeStage.BOOTSTRAP_FLUSHED)
                            {
                                bridgeState.TryTransitionStage(
                                    BridgeStage.WORLD_CRYPT_ACTIVE,
                                    "Retail CMSG_ENTER_ENCRYPTED_MODE_ACK observed.");
                            }

                            if (_options.EnableRetailWorldPacketCryptOnAck)
                            {
                                if (bridgeState.TryEnableRetailWorldCrypt(out string? enableError))
                                {
                                    _logger.LogInformation(
                                        "[WorldProxy][CRYPT] Retail world packet crypt enabled on ACK. ConnectionId={ConnectionId}",
                                        connectionId);
                                }
                                else
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][CRYPT] Failed to enable Retail world packet crypt on ACK. ConnectionId={ConnectionId}, Error={Error}",
                                        connectionId,
                                        enableError ?? "<unknown>");
                                }
                            }
                            else
                            {
                                _logger.LogInformation(
                                    "[WorldProxy][CRYPT] Retail world packet crypt-on-ACK disabled by config. ConnectionId={ConnectionId}",
                                    connectionId);
                            }

                            _logger.LogInformation(
                                "[WorldProxy][MAP] Retail CMSG_ENTER_ENCRYPTED_MODE_ACK received. ConnectionId={ConnectionId}, Signaled={Signaled}, Awaiting={Awaiting}",
                                connectionId,
                                signaled,
                                bridgeState.IsAwaitingEnterEncryptedAck);
                        },
                        onPostAckNonAckClientFrame: opcode =>
                        {
                            bool signaled = bridgeState.RegisterPostAckNonAckBootstrapTrigger(opcode);
                            if (signaled)
                            {
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Post-ACK non-ACK client frame observed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}",
                                    connectionId,
                                    opcode);
                            }
                        },
                        glueSyntheticCharEnumKickMinIntervalMs: _options.GlueSyntheticCharEnumKickMinIntervalMs,
                        onGlueSyntheticKickSuppressed: (opcode, waitMs) =>
                        {
                            _logger.LogInformation(
                                "[WorldProxy][GLUE] Synthetic CHAR_ENUM kick throttled. ConnectionId={ConnectionId}, TriggerOpcode=0x{Opcode:X8}, WaitMs={WaitMs}",
                                connectionId,
                                opcode,
                                waitMs);
                        });
                    _logger.LogInformation(
                        "[WorldProxy][MAP] Retail->AC post-auth translator enabled. ConnectionId={ConnectionId}",
                        connectionId);
                }

                if (direction == "world->client" &&
                    acorePostAuthServerTranslator is null &&
                    bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt recvCrypt))
                {
                    acorePostAuthServerTranslator = new AcorePostAuthServerTranslator(
                        recvCrypt,
                        bridgeState,
                        strictStageEnforcement: _protocolOptions.StrictStageEnforcement,
                        waitForEnterEncryptedAckGate: waitForEnterEncryptedAckGate,
                        suppressPostAuthBootstrapForProbe: _options.SuppressPostAuthBootstrapForProbe,
                        probeBareAuthResponseOnly: _options.ProbeBareAuthResponseOnly,
                        probeAuthResponseResultOnly: _options.ProbeAuthResponseResultOnly,
                        probeAuthResponseResultOnlyCode: (uint)Math.Clamp(_options.ProbeAuthResponseResultOnlyCode, 0L, uint.MaxValue),
                        probeAuthResponseMinimalSuccessNoAccountData: _options.ProbeAuthResponseMinimalSuccessNoAccountData,
                        probeAuthResponseTwwAccountDataProfile: _options.ProbeAuthResponseTwwAccountDataProfile,
                        probeAuthResponseTwwAddResultPrefix: _options.ProbeAuthResponseTwwAddResultPrefix,
                        probeAuthResponseForceWaitInfoPresent: _options.ProbeAuthResponseForceWaitInfoPresent,
                        probeAuthResponseForceCurrentBuildPresent: _options.ProbeAuthResponseForceCurrentBuildPresent,
                        probeAuthResponseAvailableClassesCardinality: _options.ProbeAuthResponseAvailableClassesCardinality,
                        probeAuthResponseTwwClassMatrixRows: _options.ProbeAuthResponseTwwClassMatrixRows,
                        probeAuthResponseTwwUseAcoreExpansionLevels: _options.ProbeAuthResponseTwwUseAcoreExpansionLevels,
                        probeInsertRetailSequencePreludeBeforeAuthResponse: _options.ProbeInsertRetailSequencePreludeBeforeAuthResponse,
                        probeInsertRetailSequencePreludeAfterAuthResponse: _options.ProbeInsertRetailSequencePreludeAfterAuthResponse,
                        probeReorderFirstDeferredFrameAfterPrelude: _options.ProbeReorderFirstDeferredFrameAfterPrelude,
                        probeFeatureSystemStatusGlueScreenTrinitySemantics: _options.ProbeFeatureSystemStatusGlueScreenTrinitySemantics,
                        probeCompressAuthResponseAsSmsgCompressedPacket: _options.ProbeCompressAuthResponseAsSmsgCompressedPacket,
                        probeCompressedAuthResponseForceEnvelope: _options.ProbeCompressedAuthResponseForceEnvelope,
                        probeCompressedAuthResponseUseRawDeflate: _options.ProbeCompressedAuthResponseUseRawDeflate,
                        probeCompressedAuthResponseUseStatefulDeflateSyncFlush: _options.ProbeCompressedAuthResponseUseStatefulDeflateSyncFlush,
                        probeCompressedAuthResponseRawDeflateLevel: _options.ProbeCompressedAuthResponseRawDeflateLevel,
                        probeCompressedAuthResponseChecksumPayloadOnly: _options.ProbeCompressedAuthResponseChecksumPayloadOnly,
                        probeCompressedAuthResponseChecksumSeed: _options.ProbeCompressedAuthResponseChecksumSeed,
                        probeCompressedAuthResponseCompressedChecksumIncludeMetadata: _options.ProbeCompressedAuthResponseCompressedChecksumIncludeMetadata,
                        probeRetailSequencePreludePayload: _probeRetailSequencePreludePayload,
                        authResponseFuzzMutation: _authResponseFuzzMutation,
                        probeAuthResponseOpcode: _probeAuthResponseOpcode,
                        probeAuthResponseReplayPayload: _probeAuthResponseReplayPayload,
                        probeAuthResponseReplayCompressedPayload: _probeAuthResponseReplayCompressedPayload,
                        probeAuthResponseReplayPatchTimeToNow: _probeAuthResponseReplayPatchTimeToNow,
                        probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount: _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount,
                        probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount: _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount,
                        probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset: _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset,
                        probeAuthResponseReplayPatchCurrentBuildPresent: _probeAuthResponseReplayPatchCurrentBuildPresent,
                        probeAuthResponseReplayPatchWaitInfoPresent: _probeAuthResponseReplayPatchWaitInfoPresent,
                        probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm: _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm,
                        probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm: _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm,
                        probeAuthResponseReplayBisectionResultOnlyErrorOk: _probeAuthResponseReplayBisectionResultOnlyErrorOk,
                        probeSetTimeZoneInformationPayload: _probeSetTimeZoneInformationPayload,
                        probeFeatureSystemStatusGlueScreenPayload: _probeFeatureSystemStatusGlueScreenPayload,
                        probeMirrorVarsPayload: _probeMirrorVarsPayload,
                        probeCacheVersionPayload: _probeCacheVersionPayload,
                        probeAvailableHotfixesPayload: _probeAvailableHotfixesPayload,
                        probeAccountDataTimesPayload: _probeAccountDataTimesPayload,
                        probeTutorialFlagsPayload: _probeTutorialFlagsPayload,
                        probeBattleNetConnectionStatusPayload: _probeBattleNetConnectionStatusPayload,
                        acoreRealmId: _options.AcoreRealmId,
                        controlledUnlockEmptyCharEnumEnabled: _options.ControlledUnlockEmptyCharEnumEnabled,
                        forwardAcoreWardenAsRetailWarden3Data: _options.ForwardAcoreWardenAsRetailWarden3Data,
                        forwardAcoreAddonInfoAsRetailAddonListRequest: _options.ForwardAcoreAddonInfoAsRetailAddonListRequest,
                        forwardAcoreTutorialFlagsAsRetailTutorialFlags: _options.ForwardAcoreTutorialFlagsAsRetailTutorialFlags,
                        getEnterEncryptedModeFrame: () =>
                        {
                            if (bridgeState.TryGetRetailEnterEncryptedModeFrame(out byte[] frame) && frame.Length > 0)
                            {
                                return frame;
                            }

                            return null;
                        },
                        onDeferredBootstrapPrepared: (payload, stagedOpcodes) =>
                        {
                            bridgeState.QueueDeferredPostAuthPayload(payload, stagedOpcodes);
                        },
                        onEnterEncryptedModeSent: () =>
                        {
                            bridgeState.TryTransitionStage(
                                BridgeStage.ENTER_ENCRYPTED_SENT,
                                "Retail SMSG_ENTER_ENCRYPTED_MODE sent.");
                        },
                        onEnterEncryptedAwaitStart: stagedOpcodes =>
                        {
                            bridgeState.BeginEnterEncryptedAwait();
                            bridgeState.MarkEnterEncryptedAwaitStart(stagedOpcodes, _options.EnterEncryptedModeAckTimeoutMs);
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Waiting for CMSG_ENTER_ENCRYPTED_MODE_ACK. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, PendingRetail={PendingRetail}",
                                connectionId,
                                _options.EnterEncryptedModeAckTimeoutMs,
                                stagedOpcodes);
                        },
                        onBootstrapFlushedWithoutAck: (bytes, stagedOpcodes) =>
                        {
                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Post-auth bootstrap flushed without ACK gate.");
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Ack-gate disabled. Flushed post-auth bootstrap immediately. ConnectionId={ConnectionId}, Bytes={Bytes}, Retail={Retail}",
                                connectionId,
                                bytes,
                                stagedOpcodes);
                        },
                        onBootstrapSuppressedForProbe: (bytes, stagedOpcodes) =>
                        {
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_suppressed_for_probe",
                                passed: false,
                                expected: "bootstrap should flush in milestone scenario",
                                actual: "bootstrap suppressed by probe mode");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Probe mode: suppressed post-auth bootstrap after ENTER_ENCRYPTED_MODE. ConnectionId={ConnectionId}, SuppressedBytes={Bytes}, Retail={Retail}",
                                connectionId,
                                bytes,
                                stagedOpcodes);
                        },
                        onCharEnumReceived: () =>
                        {
                            if (!bridgeState.TryTransitionStage(
                                    BridgeStage.CHAR_ENUM_RECEIVED,
                                    "AC SMSG_CHAR_ENUM mapped to Retail SMSG_ENUM_CHARACTERS_RESULT."))
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][STATE] CHAR_ENUM_RECEIVED transition rejected. ConnectionId={ConnectionId}, Stage={Stage}",
                                    connectionId,
                                    bridgeState.CurrentStage);
                            }
                        },
                        onControlledUnlockApplied: (acPayloadBytes, retailPayloadBytes) =>
                        {
                            _logger.LogInformation(
                                "[WorldProxy][UNLOCK] Controlled empty-char enum unlock applied. ConnectionId={ConnectionId}, AcorePayloadBytes={AcorePayloadBytes}, RetailPayloadBytes={RetailPayloadBytes}",
                                connectionId,
                                acPayloadBytes,
                                retailPayloadBytes);
                        },
                        onFrameDecoded: (opcode, payloadBytes) =>
                        {
                            // Limit frame spam while collecting first handshake map.
                            if (acServerFramesLogged < 32)
                            {
                                acServerFramesLogged++;
                                _logger.LogInformation(
                                    "[WorldProxy][AC->CLIENT FRAME] ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                                    connectionId,
                                    opcode,
                                    payloadBytes);
                            }
                        },
                        onDroppedOpcode: (opcode, payloadBytes) =>
                        {
                            _logger.LogInformation(
                                "[WorldProxy][MAP] Unmapped AC opcode dropped. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                                connectionId,
                                opcode,
                                payloadBytes);
                        });
                    _logger.LogInformation(
                        "[WorldProxy][CRYPT] AC recv header crypt enabled. ConnectionId={ConnectionId}",
                        connectionId);
                }

                if (direction == "world->client" &&
                    !firstPostAuthDumpedServer &&
                    bridgeState.TryGetAcoreHeaderCrypt(out _))
                {
                    firstPostAuthDumpedServer = true;
                    _logger.LogInformation(
                        "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, Math.Max(DefaultDumpBytes, _options.FirstPacketDumpBytes)));
                }

                if (direction == "client->world" &&
                    !firstPostAuthDumpedClient &&
                    bridgeState.TryGetAcoreHeaderCrypt(out _))
                {
                    firstPostAuthDumpedClient = true;
                    _logger.LogInformation(
                        "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, Math.Max(DefaultDumpBytes, _options.FirstPacketDumpBytes)));

                    if (RetailFrameCodec.TryDecodeRetailWorldFrame(buffer, out uint retailBodyLength, out uint retailOpcode))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][POSTAUTH-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, RetailBodyLength={RetailBodyLength}, RetailOpcode=0x{RetailOpcode:X8}",
                            connectionId,
                            direction,
                            retailBodyLength,
                            retailOpcode);
                    }
                }

                bool handledByBridge = false;
                if (direction == "world->client" &&
                    _options.EnableAcoreToRetailAuthChallengeBridgeProbe &&
                    !firstAcoreChallengeBridged &&
                    RetailAuthChallengeBuilder.TryBuildFromAcore(
                        buffer,
                        _options.RetailAuthChallengeRandomizeDosBlock,
                        out byte[] retailFrame,
                        out int consumedBytes,
                        out RetailAuthChallengeProof authChallengeProof))
                {
                    firstAcoreChallengeBridged = true;
                    handledByBridge = true;

                    if (_options.ProbeRetailAuthChallengeCountAsPreAckWorldFrame)
                    {
                        if (!bridgeState.TryProtectRetailServerFrame(
                                retailFrame,
                                out byte[] protectedAuthChallengeFrame,
                                out _,
                                out string? protectError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][CRYPT] Failed to protect bridged Retail auth challenge frame. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                protectError ?? "<unknown>");
                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        writer.Write(protectedAuthChallengeFrame);
                        totalBytes += protectedAuthChallengeFrame.Length;
                    }
                    else
                    {
                        writer.Write(retailFrame);
                        totalBytes += retailFrame.Length;
                    }

                    _logger.LogInformation(
                        "[WorldProxy][BRIDGE] Translated first AC auth challenge to Retail frame. ConnectionId={ConnectionId}, InBytes={InBytes}, OutBytes={OutBytes}",
                        connectionId,
                        consumedBytes,
                        retailFrame.Length);

                    if (_options.EnableProofPack)
                    {
                        try
                        {
                            AuthChallengeProofArtifacts artifacts = HandshakeDiagnosticsWriters.WriteAuthChallengeProofPack(
                                connectionId,
                                WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                                authChallengeProof);
                            _logger.LogInformation(
                                "[WorldProxy][PROOF] Auth challenge proof written. ConnectionId={ConnectionId}, Hex={HexPath}, Json={JsonPath}",
                                connectionId,
                                artifacts.HexPath,
                                artifacts.MetadataJsonPath);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                        {
                            _logger.LogWarning(
                                ex,
                                "[WorldProxy][PROOF] Failed to write auth challenge proof. ConnectionId={ConnectionId}",
                                connectionId);
                        }
                    }

                    if (buffer.Length > consumedBytes)
                    {
                        foreach (ReadOnlyMemory<byte> segment in buffer.Slice(consumedBytes))
                        {
                            writer.Write(segment.Span);
                            totalBytes += segment.Length;
                        }
                    }
                }
                else if (direction == "client->world" &&
                    _options.EnableRetailToAcoreAuthSessionBridge &&
                    !firstRetailAuthSessionBridged &&
                    bridgeState.TryGetAcoreAuthSeed(out uint authSeed) &&
                    RetailAuthSessionParser.TryParseRetailAuthSessionFrame(
                        buffer,
                        RetailOpcodeAuthSession,
                        RetailAuthFixedPayloadBytes,
                        out RetailAuthSessionFrame retailAuthFrame))
                {
                    if (_options.ProbeRetailAuthSessionCountAsPreAckClientFrame)
                    {
                        byte[] retailAuthWireFrame = GC.AllocateUninitializedArray<byte>(retailAuthFrame.RawFrameBytes);
                        buffer.Slice(0, retailAuthFrame.RawFrameBytes).CopyTo(retailAuthWireFrame);
                        if (!bridgeState.TryDecryptRetailClientFrame(retailAuthWireFrame, out _, out string? decryptError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][CRYPT] Failed to count Retail CMSG_AUTH_SESSION as pre-ACK client frame. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                decryptError ?? "<unknown>");
                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Counted Retail CMSG_AUTH_SESSION as pre-ACK client frame for counter continuity. ConnectionId={ConnectionId}, FrameBytes={FrameBytes}",
                            connectionId,
                            retailAuthFrame.RawFrameBytes);
                    }

                    AcoreAuthSessionBridgeResult? authBridgeResult = await TryBuildAcoreAuthSessionFrameAsync(
                            authSeed,
                            retailAuthFrame,
                            bridgeState,
                            cancellationToken)
                        .ConfigureAwait(false);

                    if (authBridgeResult is not null)
                    {
                        AcoreAuthSessionBridgeResult bridge = authBridgeResult.Value;
                        firstRetailAuthSessionBridged = true;
                        handledByBridge = true;

                        writer.Write(bridge.Frame);
                        totalBytes += bridge.Frame.Length;

                        bridgeState.TrySetAcoreHeaderCrypt(bridge.HeaderCrypt);
                        if (bridgeState.TryGetAcoreServerChallenge(out byte[] serverChallenge))
                        {
                                if (EnterEncryptedModeFramePreparer.TryPrepareRetailEnterEncryptedModeFrame(
                                    _options,
                                    bridge.SessionKey,
                                    bridge.BnetKeyData64,
                                    retailAuthFrame.LocalChallenge32,
                                    serverChallenge,
                                    defaultRetailOpcode: _enterEncryptedModeOpcode,
                                    out byte[] enterEncryptedModeFrame,
                                    out uint enterEncryptedModeOpcodeUsed,
                                    out string? enterEncryptedModeError,
                                    out string keySource,
                                    out string wireFormat,
                                    out byte[] retailWorldEncryptKey32,
                                    out EnterEncryptedModeProof proof))
                                {
                                    if (_options.EnterEncryptedModeParityGateEnabled)
                                    {
                                        string runlogsDir = WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options);
                                        string projectRoot = WorldGatewayPathResolver.ResolveProjectRoot();
                                        EnterEncryptedPayloadParityResult parity = HandshakeDiagnosticsWriters.EvaluateEnterEncryptedPayloadParity(
                                            _options,
                                            enterEncryptedModeFrame.AsSpan(20),
                                            runlogsDir,
                                            projectRoot);
                                        if (!parity.FixtureFound)
                                        {
                                            _logger.LogWarning(
                                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE fixture is unavailable. Gate skipped for this run. ConnectionId={ConnectionId}, FixturePath={FixturePath}, Error={Error}",
                                                connectionId,
                                                parity.FixturePath,
                                                parity.Error ?? "<unknown>");
                                        }
                                        else if (!parity.PayloadMatch)
                                        {
                                            _logger.LogError(
                                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload mismatch. ConnectionId={ConnectionId}, FixturePath={FixturePath}, ExpectedLen={ExpectedLen}, ActualLen={ActualLen}, DiffCount={DiffCount}, FirstDiffIndex={FirstDiffIndex}, Expected=0x{ExpectedByte:X2}, Actual=0x{ActualByte:X2}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}. Closing connection.",
                                                connectionId,
                                                parity.FixturePath,
                                                parity.ExpectedLength,
                                                parity.ActualLength,
                                                parity.DiffCount,
                                                parity.FirstDiffIndex ?? -1,
                                                parity.FirstExpectedByte ?? (byte)0,
                                                parity.FirstActualByte ?? (byte)0,
                                                parity.SignatureBytesIgnored,
                                                parity.SignatureOffset ?? -1,
                                                parity.SignatureBytes);
                                            reader.AdvanceTo(buffer.End);
                                            return totalBytes;
                                        }
                                        else
                                        {
                                            _logger.LogInformation(
                                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload parity passed. ConnectionId={ConnectionId}, FixturePath={FixturePath}, PayloadBytes={PayloadBytes}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}",
                                                connectionId,
                                                parity.FixturePath,
                                                parity.ActualLength,
                                                parity.SignatureBytesIgnored,
                                                parity.SignatureOffset ?? -1,
                                                parity.SignatureBytes);
                                        }
                                    }

                                    bridgeState.TrySetRetailEnterEncryptedModeFrame(enterEncryptedModeFrame);
                                    if (retailWorldEncryptKey32.Length == 32)
                                    {
                                        bridgeState.TrySetRetailWorldEncryptKey(retailWorldEncryptKey32);
                                    }
                                    else
                                    {
                                        _logger.LogWarning(
                                            "[WorldProxy][BRIDGE] Retail world encrypt key is unavailable. Post-ACK world packet crypto cannot be enabled. ConnectionId={ConnectionId}, KeyBytes={KeyBytes}, KeySource={KeySource}",
                                            connectionId,
                                            retailWorldEncryptKey32.Length,
                                            keySource);
                                    }
                                    _logger.LogInformation(
                                        "[WorldProxy][BRIDGE] Prepared Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, PayloadBytes={PayloadBytes}, KeySource={KeySource}, WireFormat={WireFormat}, RegionGroup={RegionGroup}, IncludeRegionGroup={IncludeRegionGroup}, Enabled={Enabled}, EnabledAsByte={EnabledAsByte}, PreferBnetKeyData={PreferBnetKeyData}",
                                        connectionId,
                                        enterEncryptedModeOpcodeUsed,
                                        enterEncryptedModeFrame.Length - 20,
                                    keySource,
                                    wireFormat,
                                    _options.EnterEncryptedModeRegionGroup,
                                    _options.EnterEncryptedModeIncludeRegionGroup,
                                    _options.EnterEncryptedModeEnabled,
                                    _options.EnterEncryptedModeEnabledAsByte,
                                    _options.EnterEncryptedModePreferBnetKeyData);

                                if (_options.EnableProofPack)
                                {
                                    try
                                    {
                                        ProofPackArtifacts artifacts = HandshakeDiagnosticsWriters.WriteEnterEncryptedProofPack(
                                            connectionId,
                                            _options,
                                            proof,
                                            bridge.AccountId,
                                            WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                                            WorldGatewayPathResolver.ResolveProjectRoot());
                                        bridgeState.SetProofPackArtifacts(artifacts.HexPath, artifacts.MetadataJsonPath, artifacts.DiffPath);
                                        _logger.LogInformation(
                                            "[WorldProxy][PROOF] Proof pack written. ConnectionId={ConnectionId}, Hex={HexPath}, Json={JsonPath}, Diff={DiffPath}",
                                            connectionId,
                                            artifacts.HexPath,
                                            artifacts.MetadataJsonPath,
                                            artifacts.DiffPath);
                                    }
                                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                                    {
                                        _logger.LogWarning(
                                            ex,
                                            "[WorldProxy][PROOF] Failed to write proof pack artifacts. ConnectionId={ConnectionId}",
                                            connectionId);
                                    }
                                }
                            }
                            else
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][BRIDGE] Failed to build Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Error={Error}",
                                    connectionId,
                                    enterEncryptedModeError ?? "<unknown>");
                            }
                        }

                        _logger.LogInformation(
                            "[WorldProxy][BRIDGE] Translated Retail CMSG_AUTH_SESSION to AC CMSG_AUTH_SESSION. ConnectionId={ConnectionId}, InBytes={InBytes}, OutBytes={OutBytes}, AccountId={AccountId}, AccountIdSource={AccountIdSource}, RegionId={RegionId}, BattlegroupId={BattlegroupId}, RetailRealmId=0x{RetailRealmId:X8}, AcoreRealmId={AcoreRealmId}",
                            connectionId,
                            retailAuthFrame.RawFrameBytes,
                            bridge.Frame.Length,
                            bridge.AccountId,
                            bridge.AccountIdSource,
                            retailAuthFrame.RegionId,
                            retailAuthFrame.BattlegroupId,
                            retailAuthFrame.RealmId,
                            _options.AcoreRealmId);
                        bridgeState.TryTransitionStage(
                            BridgeStage.AUTH_SESSION_BRIDGED,
                            "Retail CMSG_AUTH_SESSION translated to AC CMSG_AUTH_SESSION.");

                        if (buffer.Length > retailAuthFrame.RawFrameBytes)
                        {
                            foreach (ReadOnlyMemory<byte> segment in buffer.Slice(retailAuthFrame.RawFrameBytes))
                            {
                                writer.Write(segment.Span);
                                totalBytes += segment.Length;
                            }
                        }
                    }
                    else
                    {
                        _logger.LogWarning(
                            "[WorldProxy][BRIDGE] Failed to translate Retail CMSG_AUTH_SESSION in strict mode. ConnectionId={ConnectionId}. Closing connection.",
                            connectionId);

                        reader.AdvanceTo(buffer.End);
                        return totalBytes;
                    }
                }

                if (!handledByBridge)
                {
                    if (direction == "client->world" && retailPostAuthClientTranslator is not null)
                    {
                        if (!retailPostAuthClientTranslator.TryTransform(
                                buffer,
                                writer,
                                onDroppedOpcode: (opcode, payloadBytes) =>
                                {
                                    _logger.LogInformation(
                                        "[WorldProxy][MAP] Unmapped Retail opcode dropped. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, PayloadBytes={PayloadBytes}",
                                        connectionId,
                                        opcode,
                                        payloadBytes);
                                },
                                out long transformedBytes,
                                out string? transformError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][MAP] Failed to translate Retail post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                transformError ?? "<unknown>");

                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        totalBytes += transformedBytes;
                    }
                    else if (direction == "world->client" && acorePostAuthServerTranslator is not null)
                    {
                        if (!acorePostAuthServerTranslator.TryTransform(buffer, writer, out long transformedBytes, out string? transformError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][MAP] Failed to translate AC post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                transformError ?? "<unknown>");

                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        totalBytes += transformedBytes;
                    }
                    else
                    {
                        foreach (ReadOnlyMemory<byte> segment in buffer)
                        {
                            writer.Write(segment.Span);
                            totalBytes += segment.Length;
                        }
                    }
                }

                FlushResult flushResult = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                if (flushResult.IsCanceled || flushResult.IsCompleted)
                {
                    reader.AdvanceTo(buffer.End);
                    break;
                }

                if (direction == "client->world" && bridgeState.ConsumeClientRequestedDisconnect())
                {
                    _logger.LogInformation(
                        "[WorldProxy][MAP] Client requested world disconnect. ConnectionId={ConnectionId}, Direction={Direction}. Ending relay side.",
                        connectionId,
                        direction);
                    reader.AdvanceTo(buffer.End);
                    break;
                }

                if (direction == "world->client" && bridgeState.IsAwaitingEnterEncryptedAck)
                {
                    bool fallbackFlushEnabled =
                        _bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck &&
                        _options.BootstrapFlushTriggerFallbackTimeoutMs > 0;
                    int ackWaitTimeoutMs = _options.EnterEncryptedModeAckTimeoutMs;
                    if (fallbackFlushEnabled)
                    {
                        ackWaitTimeoutMs = Math.Min(ackWaitTimeoutMs, _options.BootstrapFlushTriggerFallbackTimeoutMs);
                    }

                    TimeSpan timeout = TimeSpan.FromMilliseconds(ackWaitTimeoutMs);
                    long waitStartMs = Environment.TickCount64;
                    bool acked = bridgeState.WaitForEnterEncryptedAck(timeout);
                    long elapsedMs = Environment.TickCount64 - waitStartMs;
                    bool fallbackFlushWithoutAck = false;
                    string ackExpected = fallbackFlushEnabled
                        ? $"ACK within {ackWaitTimeoutMs}ms (fallback window)"
                        : $"ACK within {_options.EnterEncryptedModeAckTimeoutMs}ms";

                    if (!acked)
                    {
                        bridgeState.TryPeekDeferredPostAuthInfo(out int pendingBytes, out string pendingRetail);
                        bridgeState.MarkEnterEncryptedAckTimeout(pendingBytes, pendingRetail);
                        if (fallbackFlushEnabled)
                        {
                            fallbackFlushWithoutAck = true;
                            bridgeState.MarkTemporalInvariant(
                                name: "enter_encrypted_ack_within_timeout",
                                passed: false,
                                expected: ackExpected,
                                actual: $"no ACK in {elapsedMs}ms; continuing with fallback bootstrap flush (pending bytes={pendingBytes})");
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_flush_trigger_fallback_timeout",
                                passed: true,
                                expected: "flush deferred bootstrap when post-ACK trigger is absent within fallback timeout",
                                actual: $"fallback timeout {ackWaitTimeoutMs}ms reached; pending retail={pendingRetail}");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] ACK not observed within fallback window. ConnectionId={ConnectionId}, FallbackTimeoutMs={TimeoutMs}, ElapsedMs={ElapsedMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}. Proceeding with deferred bootstrap flush without ACK.",
                                connectionId,
                                ackWaitTimeoutMs,
                                elapsedMs,
                                pendingBytes,
                                pendingRetail);
                        }
                        else
                        {
                            bridgeState.MarkTemporalInvariant(
                                name: "enter_encrypted_ack_within_timeout",
                                passed: false,
                                expected: ackExpected,
                                actual: $"timeout after {elapsedMs}ms (pending bytes={pendingBytes})");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Timeout waiting for CMSG_ENTER_ENCRYPTED_MODE_ACK. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, ElapsedMs={ElapsedMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}",
                                connectionId,
                                _options.EnterEncryptedModeAckTimeoutMs,
                                elapsedMs,
                                pendingBytes,
                                pendingRetail);

                            bridgeState.ResetEnterEncryptedAwait();
                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }
                    }

                    if (!fallbackFlushWithoutAck)
                    {
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] CMSG_ENTER_ENCRYPTED_MODE_ACK confirmed. ConnectionId={ConnectionId}, ElapsedMs={ElapsedMs}",
                            connectionId,
                            elapsedMs);
                        bridgeState.MarkTemporalInvariant(
                            name: "enter_encrypted_ack_within_timeout",
                            passed: true,
                            expected: ackExpected,
                            actual: $"ACK confirmed in {elapsedMs}ms");
                        bridgeState.MarkEnterEncryptedAckConfirmed(elapsedMs);
                        if (_options.EnableRetailWorldPacketCryptOnAck)
                        {
                            if (!bridgeState.TryEnableRetailWorldCrypt(out string? enableError))
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][CRYPT] Failed to enable Retail world packet crypt after ACK confirmation. ConnectionId={ConnectionId}, Error={Error}",
                                    connectionId,
                                    enableError ?? "<unknown>");
                            }
                        }
                        else
                        {
                            _logger.LogInformation(
                                "[WorldProxy][CRYPT] Retail world packet crypt-on-ACK disabled by config after ACK confirmation. ConnectionId={ConnectionId}",
                                connectionId);
                        }
                    }
                    else
                    {
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Continuing with deferred bootstrap flush without ACK confirmation due to configured fallback timeout. ConnectionId={ConnectionId}",
                            connectionId);
                    }

                    bridgeState.ResetEnterEncryptedAwait();

                    bool shouldFlushDeferredNow = true;
                    string deferredFlushPath = fallbackFlushWithoutAck ? "fallback_without_ack" : "ack_gate";
                    if (!fallbackFlushWithoutAck &&
                        _bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck)
                    {
                        int triggerTimeoutMs = _options.EnterEncryptedModeAckTimeoutMs;
                        if (_options.BootstrapFlushTriggerFallbackTimeoutMs > 0)
                        {
                            triggerTimeoutMs = Math.Min(triggerTimeoutMs, _options.BootstrapFlushTriggerFallbackTimeoutMs);
                        }

                        bridgeState.BeginPostAckNonAckBootstrapTriggerAwait();
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Deferred post-auth bootstrap flush is waiting for first post-ACK non-ACK client frame. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}",
                            connectionId,
                            triggerTimeoutMs);

                        TimeSpan triggerTimeout = TimeSpan.FromMilliseconds(triggerTimeoutMs);
                        long triggerWaitStartMs = Environment.TickCount64;
                        bool triggerObserved = bridgeState.WaitForPostAckNonAckBootstrapTrigger(triggerTimeout);
                        long triggerElapsedMs = Environment.TickCount64 - triggerWaitStartMs;
                        bridgeState.EndPostAckNonAckBootstrapTriggerAwait();

                        if (triggerObserved &&
                            bridgeState.TryGetPostAckNonAckBootstrapTriggerOpcode(out uint triggerOpcode))
                        {
                            deferredFlushPath = "post_ack_non_ack_trigger";
                            bridgeState.MarkPostAckNonAckBootstrapTriggerWait(triggerElapsedMs);
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_flush_trigger_post_ack_non_ack",
                                passed: true,
                                expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                                actual: $"triggered by opcode=0x{triggerOpcode:X8} after {triggerElapsedMs}ms");
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger fired. ConnectionId={ConnectionId}, TriggerOpcode=0x{Opcode:X8}, WaitMs={WaitMs}",
                                connectionId,
                                triggerOpcode,
                                triggerElapsedMs);
                        }
                        else
                        {
                            bridgeState.TryPeekDeferredPostAuthInfo(out int pendingBytes, out string pendingRetail);
                            bool fallbackFlushOnTriggerTimeout = _options.BootstrapFlushTriggerFallbackTimeoutMs > 0;
                            if (fallbackFlushOnTriggerTimeout)
                            {
                                shouldFlushDeferredNow = true;
                                deferredFlushPath = "post_ack_non_ack_fallback_timeout";
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_trigger_post_ack_non_ack",
                                    passed: false,
                                    expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                                    actual: $"timeout after {triggerElapsedMs}ms; fallback flush enabled (pending bytes={pendingBytes}, pending retail={pendingRetail})");
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_trigger_post_ack_non_ack_fallback",
                                    passed: true,
                                    expected: "flush deferred bootstrap on trigger-timeout when fallback timeout is configured",
                                    actual: $"fallback timeout {triggerTimeoutMs}ms reached; flushing pending retail={pendingRetail}");
                                _logger.LogWarning(
                                    "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, WaitMs={WaitMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}. Proceeding with fallback flush.",
                                    connectionId,
                                    triggerTimeoutMs,
                                    triggerElapsedMs,
                                    pendingBytes,
                                    pendingRetail);
                            }
                            else
                            {
                                shouldFlushDeferredNow = false;
                                deferredFlushPath = "post_ack_non_ack_timeout_no_flush";
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_trigger_post_ack_non_ack",
                                    passed: false,
                                    expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                                    actual: $"timeout after {triggerElapsedMs}ms (pending bytes={pendingBytes}, pending retail={pendingRetail})");
                                _logger.LogWarning(
                                    "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, WaitMs={WaitMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}",
                                    connectionId,
                                    triggerTimeoutMs,
                                    triggerElapsedMs,
                                    pendingBytes,
                                    pendingRetail);
                            }
                        }
                    }

                    bridgeState.MarkDeferredFlushPath(deferredFlushPath);
                    if (shouldFlushDeferredNow &&
                        bridgeState.TryTakeDeferredPostAuthPayload(out byte[] deferredPayload, out string stagedOpcodes) &&
                        deferredPayload.Length > 0)
                    {
                        if (_options.SuppressPostAuthBootstrapForProbe && !_options.ProbeBareAuthResponseOnly)
                        {
                            bridgeState.MarkDeferredFlushPath("suppressed");
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_suppressed_for_probe",
                                passed: false,
                                expected: "bootstrap should flush in milestone scenario",
                                actual: "bootstrap suppressed by probe mode");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Probe mode: suppressed deferred post-auth bootstrap after ACK gate. ConnectionId={ConnectionId}, SuppressedBytes={Bytes}, Retail={Retail}",
                                connectionId,
                                deferredPayload.Length,
                                stagedOpcodes);
                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Deferred post-auth bootstrap suppressed by probe mode after ACK gate.");

                            if (_options.ProbeExplicitBootstrapFlushMarker)
                            {
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_marker_explicit",
                                    passed: true,
                                    expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                                    actual: $"path=suppressed;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                                    connectionId,
                                    "suppressed",
                                    deferredPayload.Length,
                                    stagedOpcodes);
                            }
                        }
                        else if (!RetailFrameCodec.TrySplitRetailWorldFrames(deferredPayload, out List<RetailFrameChunk> deferredFrames, out string? splitError))
                        {
                            bridgeState.MarkDeferredFlushPath("raw_payload_fallback");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Failed to split deferred post-auth bootstrap into Retail frames. ConnectionId={ConnectionId}, Error={Error}, Bytes={Bytes}, Retail={Retail}",
                                connectionId,
                                splitError ?? "<unknown>",
                                deferredPayload.Length,
                                stagedOpcodes);

                            writer.Write(deferredPayload);
                            totalBytes += deferredPayload.Length;

                            FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                            if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
                            {
                                reader.AdvanceTo(buffer.End);
                                break;
                            }

                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Deferred post-auth bootstrap flushed after ACK gate (raw payload fallback).");

                            if (_options.ProbeExplicitBootstrapFlushMarker)
                            {
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_marker_explicit",
                                    passed: true,
                                    expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                                    actual: $"path=raw_payload_fallback;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                                    connectionId,
                                    "raw_payload_fallback",
                                    deferredPayload.Length,
                                    stagedOpcodes);
                            }
                        }
                        else
                        {
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Flushing deferred post-auth bootstrap. ConnectionId={ConnectionId}, Frames={Frames}, Bytes={Bytes}, Retail={Retail}",
                                connectionId,
                                deferredFrames.Count,
                                deferredPayload.Length,
                                stagedOpcodes);

                            bridgeState.BeginDeferredBootstrapFlush(deferredFrames.Count);
                            bool deferredInterrupted = false;
                            for (int frameIndex = 0; frameIndex < deferredFrames.Count; frameIndex++)
                            {
                                RetailFrameChunk frame = deferredFrames[frameIndex];
                                bool shouldDropFrame = _probeDropDeferredOpcodes.Contains(frame.Opcode);
                                if (_options.ProbeBareAuthResponseOnly &&
                                    frame.Opcode == RetailOpcodeSmsgAuthResponse)
                                {
                                    // In bare AUTH_RESPONSE probe mode, always deliver AUTH_RESPONSE even if
                                    // legacy probe drop list still includes it from previous experiments.
                                    shouldDropFrame = false;
                                }

                                if (shouldDropFrame)
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][HANDSHAKE] Probe mode: dropped deferred frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, BodyLength={BodyLength}",
                                        connectionId,
                                        frameIndex + 1,
                                        deferredFrames.Count,
                                        frame.Opcode,
                                        frame.BodyLength);
                                    continue;
                                }

                                bool isPreludeFrame = frame.Opcode == RetailOpcodeSmsgAuthSequencePrelude;
                                bool isAuthResponseFrame = frame.Opcode == _probeAuthResponseOpcode;
                                if (isAuthResponseFrame)
                                {
                                    bool plainEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(frame.Frame, out string plainEnvelopeActual);
                                    bridgeState.MarkTemporalInvariant(
                                        name: "auth_response_plaintext_envelope_invariant",
                                        passed: plainEnvelopeOk,
                                        expected: "plaintext frame: size=opcode+payload, frame_bytes=16+size, size excludes 12-byte tag",
                                        actual: plainEnvelopeActual);

                                    if (!plainEnvelopeOk)
                                    {
                                        _logger.LogWarning(
                                            "[WorldProxy][ENVELOPE] Plain AUTH_RESPONSE envelope invariant failed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Actual={Actual}",
                                            connectionId,
                                            frame.Opcode,
                                            plainEnvelopeActual);
                                    }
                                }

                                if (!bridgeState.TryProtectRetailServerFrame(
                                        frame.Frame,
                                        out byte[] protectedFrame,
                                        out ulong serverCounterUsed,
                                        out string? protectError))
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][CRYPT] Failed to protect deferred Retail frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, Error={Error}",
                                        connectionId,
                                        frameIndex + 1,
                                        deferredFrames.Count,
                                        frame.Opcode,
                                        protectError ?? "<unknown>");

                                    reader.AdvanceTo(buffer.End);
                                    return totalBytes;
                                }

                                string plainSha256 = Convert.ToHexString(SHA256.HashData(frame.Frame));
                                string protectedSha256 = Convert.ToHexString(SHA256.HashData(protectedFrame));
                                string protectedTagHex = Convert.ToHexString(protectedFrame.AsSpan(4, 12));
                                DeferredFrameParityResult deferredParity = new(
                                    Status: "not_evaluated",
                                    FixturePath: null,
                                    DiffOffset: null,
                                    ExpectedBytes: null,
                                    ActualBytes: null);

                                if (isPreludeFrame)
                                {
                                    bool protectedEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(protectedFrame, out string preludeEnvelopeActual);
                                    uint protectedSize = protectedEnvelopeOk
                                        ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(0, 4))
                                        : 0u;
                                    uint protectedOpcode = protectedEnvelopeOk
                                        ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(16, 4))
                                        : 0u;
                                    bool sizePreserved = protectedEnvelopeOk &&
                                        protectedSize == (uint)frame.BodyLength &&
                                        protectedFrame.Length == frame.Frame.Length;
                                    bool opcodeEncryptedWhenCryptActive = !bridgeState.IsRetailWorldCryptActive ||
                                        protectedOpcode != frame.Opcode;
                                    bool preludeInvariantPassed = sizePreserved && opcodeEncryptedWhenCryptActive;
                                    bridgeState.MarkTemporalInvariant(
                                        name: "prelude_encrypted_envelope_invariant",
                                        passed: preludeInvariantPassed,
                                        expected: "if world crypt is active, prelude opcode bytes must be encrypted while envelope size stays preserved",
                                        actual: $"{preludeEnvelopeActual};world_crypt_active={bridgeState.IsRetailWorldCryptActive};plain_opcode=0x{frame.Opcode:X8};protected_opcode=0x{protectedOpcode:X8};size_preserved={sizePreserved}");

                                    _logger.LogInformation(
                                        "[WorldProxy][ENVELOPE] Prelude frame protected. ConnectionId={ConnectionId}, PlainOpcode=0x{PlainOpcode:X8}, ProtectedOpcode=0x{ProtectedOpcode:X8}, WorldCryptActive={WorldCryptActive}, SizePreserved={SizePreserved}",
                                        connectionId,
                                        frame.Opcode,
                                        protectedOpcode,
                                        bridgeState.IsRetailWorldCryptActive,
                                        sizePreserved);
                                }

                                if (isAuthResponseFrame)
                                {
                                    bool protectedEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(protectedFrame, out string protectedEnvelopeActual);
                                    uint protectedSize = protectedEnvelopeOk
                                        ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(0, 4))
                                        : 0u;
                                    bool sizePreserved = protectedEnvelopeOk &&
                                        protectedSize == (uint)frame.BodyLength &&
                                        protectedFrame.Length == frame.Frame.Length;
                                    bridgeState.MarkTemporalInvariant(
                                        name: "auth_response_encrypted_envelope_invariant",
                                        passed: sizePreserved,
                                        expected: "encrypted frame keeps plaintext size and total length (16+size), with 12-byte tag in header",
                                        actual: $"{protectedEnvelopeActual};size_preserved={sizePreserved};expected_body={frame.BodyLength};protected_size={protectedSize};protected_bytes={protectedFrame.Length};plain_bytes={frame.Frame.Length}");

                                    if (!sizePreserved)
                                    {
                                        _logger.LogWarning(
                                            "[WorldProxy][ENVELOPE] Encrypted AUTH_RESPONSE envelope invariant failed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Actual={Actual}",
                                            connectionId,
                                            frame.Opcode,
                                            protectedEnvelopeActual);
                                    }
                                }

                                if (frameIndex == 0)
                                {
                                    deferredParity = HandshakeDiagnosticsWriters.EvaluateFirstDeferredFrameParity(
                                        _options.ProbeFirstDeferredFrameParityFixturePath,
                                        protectedFrame,
                                        WorldGatewayPathResolver.ResolveProjectRoot());
                                    bool parityConfigured = !string.IsNullOrWhiteSpace(_options.ProbeFirstDeferredFrameParityFixturePath);
                                    bool parityPassed = !parityConfigured ||
                                        string.Equals(deferredParity.Status, "match", StringComparison.OrdinalIgnoreCase);
                                    string parityExpected = parityConfigured
                                        ? "first deferred protected frame should byte-match configured fixture"
                                        : "fixture not configured; parity check is informational only";
                                    string parityActual = $"status={deferredParity.Status};fixture={deferredParity.FixturePath ?? "<none>"};diff_offset={deferredParity.DiffOffset?.ToString(CultureInfo.InvariantCulture) ?? "<none>"};expected={deferredParity.ExpectedBytes ?? "<none>"};actual={deferredParity.ActualBytes ?? "<none>"}";
                                    bridgeState.MarkTemporalInvariant(
                                        name: "deferred_first_frame_fixture_parity",
                                        passed: parityPassed,
                                        expected: parityExpected,
                                        actual: parityActual);

                                    _logger.LogInformation(
                                        "[WorldProxy][HANDSHAKE] First deferred frame evidence. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Counter={Counter}, Tag={Tag}, PlainSha256={PlainSha256}, ProtectedSha256={ProtectedSha256}, ParityStatus={ParityStatus}, ParityDiffOffset={ParityDiffOffset}, ParityFixture={ParityFixture}",
                                        connectionId,
                                        frame.Opcode,
                                        serverCounterUsed,
                                        protectedTagHex,
                                        plainSha256,
                                        protectedSha256,
                                        deferredParity.Status,
                                        deferredParity.DiffOffset,
                                        deferredParity.FixturePath ?? "<none>");
                                }

                                writer.Write(protectedFrame);
                                totalBytes += protectedFrame.Length;

                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Sent deferred frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, BodyLength={BodyLength}, FrameBytes={FrameBytes}, Counter={Counter}, Tag={Tag}",
                                    connectionId,
                                    frameIndex + 1,
                                    deferredFrames.Count,
                                    frame.Opcode,
                                    frame.BodyLength,
                                    protectedFrame.Length,
                                    serverCounterUsed,
                                    protectedTagHex);

                                bridgeState.MarkDeferredFrameSent(
                                    frameIndex + 1,
                                    deferredFrames.Count,
                                    frame.Opcode,
                                    frame.BodyLength,
                                    protectedFrame.Length,
                                    serverCounterUsed,
                                    plainSha256,
                                    protectedSha256,
                                    protectedTagHex,
                                    deferredParity);

                                FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                                if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][HANDSHAKE] Deferred frame flush interrupted. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}",
                                        connectionId,
                                        frameIndex + 1,
                                        deferredFrames.Count,
                                        frame.Opcode);

                                    deferredInterrupted = true;
                                    break;
                                }
                            }

                            if (deferredInterrupted)
                            {
                                reader.AdvanceTo(buffer.End);
                                return totalBytes;
                            }

                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Deferred post-auth bootstrap flushed after ACK gate.");

                            if (_options.ProbeExplicitBootstrapFlushMarker)
                            {
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_marker_explicit",
                                    passed: true,
                                    expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                                    actual: $"path=protected_frames;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                                    connectionId,
                                    "protected_frames",
                                    deferredPayload.Length,
                                    stagedOpcodes);
                            }
                        }
                    }
                }
            }

            reader.AdvanceTo(buffer.End);

            if (readResult.IsCanceled || readResult.IsCompleted)
            {
                break;
            }
        }

        return totalBytes;
    }

    private async ValueTask<bool> TryPerformRetailConnectionInitializerAsync(
        uint connectionId,
        NetworkStream downstreamStream,
        CancellationToken relayToken)
    {
        using var initCts = CancellationTokenSource.CreateLinkedTokenSource(relayToken);
        initCts.CancelAfter(_options.InitializerTimeoutMs);

        try
        {
            await downstreamStream.WriteAsync(ServerConnectionInitializer, initCts.Token).ConfigureAwait(false);
            await downstreamStream.FlushAsync(initCts.Token).ConfigureAwait(false);

            byte[] rented = ArrayPool<byte>.Shared.Rent(ClientConnectionInitializer.Length);
            try
            {
                Memory<byte> clientInit = rented.AsMemory(0, ClientConnectionInitializer.Length);
                bool ok = await WorldProxyRuntimeHelpers.TryReadExactAsync(downstreamStream, clientInit, initCts.Token).ConfigureAwait(false);
                if (!ok)
                {
                    _logger.LogWarning(
                        "[WorldProxy][INIT] Failed to read client initializer. ConnectionId={ConnectionId}, ExpectedBytes={ExpectedBytes}",
                        connectionId,
                        ClientConnectionInitializer.Length);
                    return false;
                }

                ReadOnlySpan<byte> expected = ClientConnectionInitializer;
                if (!clientInit.Span.SequenceEqual(expected))
                {
                    _logger.LogWarning(
                        "[WorldProxy][INIT] Invalid client initializer. ConnectionId={ConnectionId}, Expected=\"{Expected}\", ActualHex={ActualHex}",
                        connectionId,
                        Encoding.ASCII.GetString(ClientConnectionInitializer),
                        Convert.ToHexString(clientInit.Span));
                    return false;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }

            _logger.LogInformation(
                "[WorldProxy][INIT] Retail world initializer completed. ConnectionId={ConnectionId}",
                connectionId);
            return true;
        }
        catch (OperationCanceledException) when (initCts.IsCancellationRequested)
        {
            _logger.LogWarning(
                "[WorldProxy][INIT] Retail world initializer timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}",
                connectionId,
                _options.InitializerTimeoutMs);
            return false;
        }
        catch (IOException ex)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][INIT] IO error during retail initializer. ConnectionId={ConnectionId}",
                connectionId);
            return false;
        }
        catch (SocketException ex)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][INIT] Socket error during retail initializer. ConnectionId={ConnectionId}",
                connectionId);
            return false;
        }
    }

    private async ValueTask<AcoreAuthSessionBridgeResult?> TryBuildAcoreAuthSessionFrameAsync(
        uint authSeed,
        RetailAuthSessionFrame retailFrame,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        try
        {
            int accountId = retailFrame.AccountId;
            string accountIdSource = "retail_payload";
            if (accountId <= 0)
            {
                (accountId, accountIdSource) = await ResolveMissingRetailAccountIdAsync(cancellationToken).ConfigureAwait(false);
                if (accountId > 0)
                {
                    _logger.LogWarning(
                        "[WorldProxy][DB-GATE] Retail AUTH_SESSION accountId missing. Using fallback account id. AccountId={AccountId}, Source={Source}",
                        accountId,
                        accountIdSource);
                }
                else
                {
                    bridgeState.SetEvidenceContext("DB", "db parity gate");
                    bridgeState.MarkTemporalInvariant(
                        name: "db_parity_gate",
                        passed: false,
                        expected: "Retail AUTH_SESSION carries a non-zero accountId or fallback resolution finds one.",
                        actual: "Retail AUTH_SESSION accountId is missing and no fallback account id is available.");
                    _logger.LogWarning(
                        "[WorldProxy][DB-GATE] Rejected before protocol rewrite: Retail auth session has no valid accountId and fallback resolution failed.");
                    return null;
                }
            }

            AcoreSessionMaterial? material = await _worldSessionMaterialRepository.TryReadSessionMaterialByAccountIdAsync(accountId, cancellationToken).ConfigureAwait(false);
            if (material is null && accountIdSource == "config:AuthAccountIdFallback")
            {
                int? latestAccountId = await _worldSessionMaterialRepository.TryReadLatestSessionMaterialAccountIdAsync(cancellationToken).ConfigureAwait(false);
                if (latestAccountId is > 0 && latestAccountId.Value != accountId)
                {
                    AcoreSessionMaterial? latestMaterial = await _worldSessionMaterialRepository.TryReadSessionMaterialByAccountIdAsync(latestAccountId.Value, cancellationToken).ConfigureAwait(false);
                    if (latestMaterial is not null)
                    {
                        accountId = latestAccountId.Value;
                        accountIdSource = "db:adapter_world_session_material.latest";
                        material = latestMaterial;
                        _logger.LogWarning(
                            "[WorldProxy][DB-GATE] AuthAccountIdFallback had no session material; switched to latest adapter world session material. AccountId={AccountId}",
                            accountId);
                    }
                }
            }

            if (material is null)
            {
                bridgeState.SetEvidenceContext("DB", "db parity gate");
                bridgeState.MarkTemporalInvariant(
                    name: "db_parity_gate",
                    passed: false,
                    expected: "Account/session material exists in auth DB for resolved account id.",
                    actual: $"No DB row/material for account id {accountId} (source={accountIdSource}).");
                _logger.LogWarning(
                    "[WorldProxy][BRIDGE] Strict session key lookup failed for AccountId={AccountId}, Source={Source}.",
                    accountId,
                    accountIdSource);
                return null;
            }

            AcoreSessionMaterial account = material.Value;
            RetailAuthSessionFrame effectiveRetailFrame = retailFrame with { AccountId = accountId };
            DbParityGateResult dbGateResult = DbParityGateEvaluator.Evaluate(
                effectiveRetailFrame,
                account,
                AcoreSessionKeyBytes,
                _options.AcoreRealmId,
                _options.AcoreClientBuild);
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: dbGateResult.Passed,
                expected: dbGateResult.Expected,
                actual: dbGateResult.Actual);
            if (!dbGateResult.Passed)
            {
                bridgeState.SetEvidenceContext("DB", "db parity gate");
                _logger.LogWarning(
                    "[WorldProxy][DB-GATE] Rejected before protocol rewrite. AccountId={AccountId}, Reason={Reason}",
                    account.AccountId,
                    dbGateResult.FailureReason);
                return null;
            }

            byte[] digest = AcoreAuthSessionBuilder.BuildAcoreDigest(
                account.AccountName,
                retailFrame.LocalChallenge4,
                authSeed,
                account.SessionKey,
                Sha1ZeroPrefix,
                AcoreDigestBytes);

            byte[] addonInfo = AcoreAuthSessionBuilder.BuildMinimalAddonInfoBlob();
            byte[] payload = AcoreAuthSessionBuilder.BuildAcoreAuthSessionPayload(
                effectiveRetailFrame,
                account.AccountName,
                digest,
                addonInfo,
                _options.AcoreClientBuild,
                _options.AcoreRealmId);
            byte[] frame = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeAuthSession, payload);
            var authCrypt = new AuthCrypt();
            authCrypt.Init(account.SessionKey);

            CryptographicOperations.ZeroMemory(digest);
            return new AcoreAuthSessionBridgeResult(frame, authCrypt, account.SessionKey, account.BnetKeyData64, accountId, accountIdSource);
        }
        catch (Exception ex) when (ex is MySqlException or IOException or CryptographicException or InvalidOperationException)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][BRIDGE] Exception while building AC auth session frame.");
            bridgeState.SetEvidenceContext("DB", "db parity gate");
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: false,
                expected: "DB parity gate should pass without runtime exceptions.",
                actual: ex.GetType().Name);
            return null;
        }
    }

    private async ValueTask<(int AccountId, string Source)> ResolveMissingRetailAccountIdAsync(CancellationToken cancellationToken)
    {
        if (_options.AuthAccountIdFallback > 0)
        {
            return (_options.AuthAccountIdFallback, "config:AuthAccountIdFallback");
        }

        int? latestAccountId = await _worldSessionMaterialRepository.TryReadLatestSessionMaterialAccountIdAsync(cancellationToken).ConfigureAwait(false);
        if (latestAccountId is > 0)
        {
            return (latestAccountId.Value, "db:adapter_world_session_material.latest");
        }

        return (0, "none");
    }


}
