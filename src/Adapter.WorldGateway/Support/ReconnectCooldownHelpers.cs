using System.Collections.Concurrent;

namespace Adapter.WorldGateway;

internal static class ReconnectCooldownHelpers
{
    public static bool TryGetRemainingMs(
        ConcurrentDictionary<string, long> cooldownUntilByKey,
        int cooldownMs,
        string downstreamKey,
        out int remainingMs)
    {
        remainingMs = 0;

        if (cooldownMs <= 0 || string.IsNullOrWhiteSpace(downstreamKey))
        {
            return false;
        }

        long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (!cooldownUntilByKey.TryGetValue(downstreamKey, out long cooldownUntilUnixMs))
        {
            return false;
        }

        long deltaMs = cooldownUntilUnixMs - nowUnixMs;
        if (deltaMs <= 0)
        {
            cooldownUntilByKey.TryRemove(downstreamKey, out _);
            return false;
        }

        remainingMs = deltaMs > int.MaxValue ? int.MaxValue : (int)deltaMs;
        return true;
    }

    public static bool TryArm(
        ConcurrentDictionary<string, long> cooldownUntilByKey,
        int cooldownMs,
        string downstreamKey,
        out long cooldownUntilUnixMs)
    {
        cooldownUntilUnixMs = 0;
        if (cooldownMs <= 0 || string.IsNullOrWhiteSpace(downstreamKey))
        {
            return false;
        }

        long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        long targetCooldownUntilUnixMs = checked(nowUnixMs + cooldownMs);
        cooldownUntilUnixMs = targetCooldownUntilUnixMs;
        cooldownUntilByKey.AddOrUpdate(
            downstreamKey,
            targetCooldownUntilUnixMs,
            (_, existing) => Math.Max(existing, targetCooldownUntilUnixMs));
        return true;
    }
}
