namespace Adapter.WorldGateway;

internal enum RelayFailureRecoveryPolicy
{
    CancelSiblingAndClose = 0,
    CancelSiblingDrainAndClose = 1
}
