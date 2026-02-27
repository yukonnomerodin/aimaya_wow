using System.Net;
using System.Net.Sockets;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void InitializeListenerAndLogStartupState()
    {
        (IPAddress bindAddress, bool resolvedAckGate, string ackGateSource) = StartListenerAndResolveStartupContext();
        LogStartupProbeWarnings();
        LogStartupSummary(bindAddress, resolvedAckGate, ackGateSource);
    }

    private (IPAddress BindAddress, bool ResolvedAckGate, string AckGateSource) StartListenerAndResolveStartupContext()
    {
        IPAddress bindAddress = WorldProxyConfigParsers.ParseBindAddress(_options.ListenAddress);
        bool resolvedAckGate = AckPolicyResolver.ResolveEffectiveWaitForAckGate(
            _ackPolicyMode,
            _options.EnterEncryptedModeAckGateEnabled,
            _protocolOptions.AckPolicy,
            _protocolOptions.AckPolicyDecisionPath,
            out string ackGateSource);
        _listener = new TcpListener(bindAddress, _options.ListenPort);
        _listener.Server.NoDelay = true;
        _listener.Start(_options.Backlog);

        return (bindAddress, resolvedAckGate, ackGateSource);
    }
}
