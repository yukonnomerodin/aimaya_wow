using System;
using System.Collections.Generic;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
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
