namespace Adapter.WorldGateway;

internal static class WorldGatewayPathResolver
{
    public static string EnsureHandshakeRunlogsDirectory(WorldProxyOptions options)
    {
        string runlogsDir = Path.Combine(ResolveProofPackRoot(options), "runlogs");
        Directory.CreateDirectory(runlogsDir);
        return runlogsDir;
    }

    public static string ResolveProofPackRoot(WorldProxyOptions options)
    {
        if (Path.IsPathRooted(options.ProofPackRootPath))
        {
            return options.ProofPackRootPath;
        }

        string root = ResolveProjectRoot();
        return Path.Combine(root, options.ProofPackRootPath);
    }

    public static string ResolveProjectRoot()
    {
        string? current = Directory.GetCurrentDirectory();
        string? resolved = TryResolveProjectRootFrom(current);
        if (!string.IsNullOrEmpty(resolved))
        {
            return resolved;
        }

        string? fromBase = TryResolveProjectRootFrom(AppContext.BaseDirectory);
        if (!string.IsNullOrEmpty(fromBase))
        {
            return fromBase;
        }

        return current ?? AppContext.BaseDirectory;
    }

    private static string? TryResolveProjectRootFrom(string? startPath)
    {
        if (string.IsNullOrWhiteSpace(startPath))
        {
            return null;
        }

        var dir = new DirectoryInfo(startPath);
        while (dir is not null)
        {
            bool hasSolution = File.Exists(Path.Combine(dir.FullName, "aimaya_wow.sln"));
            bool hasSrc = Directory.Exists(Path.Combine(dir.FullName, "src", "Adapter.WorldGateway"));
            if (hasSolution || hasSrc)
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return null;
    }
}
