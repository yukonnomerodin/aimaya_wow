namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ValidateProtocolExperimentContractOrThrow();

        InitializeListenerAndLogStartupState();

        try
        {
            await RunAcceptLoopAsync(stoppingToken).ConfigureAwait(false);
        }
        finally
        {
            await StopListenerAndAwaitActiveConnectionsAsync().ConfigureAwait(false);
        }
    }
}
