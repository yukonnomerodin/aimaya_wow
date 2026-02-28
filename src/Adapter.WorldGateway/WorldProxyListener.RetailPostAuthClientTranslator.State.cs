using System;
using System.Collections.Generic;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class RetailPostAuthClientTranslator
    {
        private readonly AuthCrypt _authCrypt;
        private readonly WorldProxyBridgeState _bridgeState;
        private readonly bool _strictStageEnforcement;
        private readonly byte[] _sizePrefix = new byte[4];
        private readonly HashSet<uint> _loggedDroppedOpcodes = new();
        private readonly Action<uint>? _onLogDisconnect;
        private readonly Action? _onEnumCharactersRequest;
        private readonly Action? _onEnterEncryptedModeAck;
        private readonly Action<uint>? _onPostAckNonAckClientFrame;
        private readonly int _glueSyntheticCharEnumKickMinIntervalMs;
        private readonly Action<uint, int>? _onGlueSyntheticKickSuppressed;

        private int _sizePrefixRead;
        private byte[] _frameBuffer = Array.Empty<byte>();
        private int _frameBytesRead;
        private int _frameExpectedBytes;
        private long _lastGlueSyntheticKickUnixMs = long.MinValue;
    }
}
