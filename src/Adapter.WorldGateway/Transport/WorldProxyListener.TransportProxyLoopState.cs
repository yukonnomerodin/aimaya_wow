namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed class TransportProxyLoopState
    {
        public bool FirstChunkDumped { get; set; }
        public bool FirstAcoreChallengeBridged { get; set; }
        public bool FirstRetailAuthSessionBridged { get; set; }
        public bool FirstPostAuthDumpedClient { get; set; }
        public bool FirstPostAuthDumpedServer { get; set; }
        public int AcoreServerFramesLogged { get; set; }
        public RetailPostAuthClientTranslator? RetailPostAuthClientTranslator { get; set; }
        public AcorePostAuthServerTranslator? AcorePostAuthServerTranslator { get; set; }
    }
}
