namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
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
