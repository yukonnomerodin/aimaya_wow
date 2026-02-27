using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly object _activeConnectionsLock = new();
    private readonly List<Task> _activeConnections = new();
    private TcpListener? _listener;
    private int _connectionSequence;
}
