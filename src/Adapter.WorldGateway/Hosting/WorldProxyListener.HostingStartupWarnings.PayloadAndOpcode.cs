using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void LogStartupProbePayloadAndOpcodeWarnings()
    {
        LogStartupProbeOpcodeAndPreludeWarnings();
        LogStartupProbePayloadReplayWarnings();
    }
}
