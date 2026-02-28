namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void LogStartupProbeWarnings()
    {
        LogStartupProbePayloadAndOpcodeWarnings();
        LogStartupProbeBehaviorWarnings();
        LogStartupProbeCompressionCryptAndParityWarnings();
        LogStartupProbeFuzzerWarnings();
    }
}
