using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Adapter.AuthGateway.Database;

namespace Adapter.AuthGateway;

internal static class RealmListPacketBuilder
{
    private const byte DefaultRealmType = 0; // Normal
    private const uint DefaultRealmFlags = 0; // Online + compatible
    private const uint DefaultClientBuild = 66017; // WoW 12.0.1.66017

    private static readonly byte[] JsonRealmListUpdatesPrefix = "JSONRealmListUpdates:"u8.ToArray();
    private static readonly byte[] JsonRealmCharacterCountListPrefix = "JSONRealmCharacterCountList:"u8.ToArray();
    private static readonly byte[] JsonRealmListServerIpAddressesPrefix = "JSONRealmListServerIPAddresses:"u8.ToArray();

    public static bool TryBuildRetailPayload(
        IReadOnlyList<RealmData> realms,
        out ArrayBufferWriter<byte> writer)
    {
        writer = new ArrayBufferWriter<byte>(Math.Max(128, 64 * realms.Count));
        var packetWriter = new SpanPacketWriter(writer);

        if (!packetWriter.TryWriteUInt32((uint)realms.Count))
        {
            return false;
        }

        for (int i = 0; i < realms.Count; i++)
        {
            RealmData realm = realms[i];
            string address = BuildAddress(realm);
            float population = ClampPopulation(realm.Population);
            uint category = realm.Timezone;

            if (!packetWriter.TryWriteByte(DefaultRealmType) ||
                !packetWriter.TryWriteUInt32(DefaultRealmFlags) ||
                !packetWriter.TryWriteUtf8String16(realm.Name) ||
                !packetWriter.TryWriteUtf8String16(address) ||
                !packetWriter.TryWriteSingle(population) ||
                !packetWriter.TryWriteUInt32(0) || // character count is not available in this stage
                !packetWriter.TryWriteUInt32(category))
            {
                return false;
            }
        }

        return true;
    }

    public static bool TryBuildBnetRealmListBlobs(
        IReadOnlyList<RealmData> realms,
        string? requestedSubRegion,
        out byte[] realmListBlob,
        out byte[] characterCountBlob,
        uint clientBuild = DefaultClientBuild)
    {
        realmListBlob = Array.Empty<byte>();
        characterCountBlob = Array.Empty<byte>();

        List<RealmData> visibleRealms = FilterBySubRegion(realms, requestedSubRegion);

        byte[] realmListJson = BuildRealmListUpdatesJson(visibleRealms, clientBuild);
        if (!TryCompressPrefixedJson(JsonRealmListUpdatesPrefix, realmListJson, out realmListBlob))
        {
            return false;
        }

        byte[] characterCountJson = BuildRealmCharacterCountListJson(visibleRealms);
        if (!TryCompressPrefixedJson(JsonRealmCharacterCountListPrefix, characterCountJson, out characterCountBlob))
        {
            return false;
        }

        return true;
    }

    public static bool TryBuildBnetServerAddressesBlob(RealmData realm, out byte[] serverAddressesBlob)
    {
        serverAddressesBlob = Array.Empty<byte>();

        byte[] json = BuildRealmListServerIpAddressesJson(realm);
        return TryCompressPrefixedJson(JsonRealmListServerIpAddressesPrefix, json, out serverAddressesBlob);
    }

    private static string BuildAddress(RealmData realm)
    {
        string host = string.IsNullOrWhiteSpace(realm.Address) ? "127.0.0.1" : realm.Address.Trim();
        return string.Create(
            host.Length + 1 + realm.Port.ToString().Length,
            (Host: host, Port: realm.Port),
            static (span, state) =>
            {
                state.Host.AsSpan().CopyTo(span);
                int offset = state.Host.Length;
                span[offset++] = ':';
                _ = state.Port.TryFormat(span[offset..], out _, provider: null);
            });
    }

    private static float ClampPopulation(float value)
    {
        if (float.IsNaN(value) || float.IsInfinity(value))
        {
            return 0f;
        }

        return Math.Clamp(value, 0f, 1f);
    }

    private static List<RealmData> FilterBySubRegion(IReadOnlyList<RealmData> realms, string? requestedSubRegion)
    {
        if (string.IsNullOrWhiteSpace(requestedSubRegion))
        {
            return new List<RealmData>(realms);
        }

        string filter = requestedSubRegion.Trim();
        var filtered = new List<RealmData>(realms.Count);

        for (int i = 0; i < realms.Count; i++)
        {
            RealmData realm = realms[i];
            if (BuildSubRegionAddress(realm).Equals(filter, StringComparison.OrdinalIgnoreCase))
            {
                filtered.Add(realm);
            }
        }

        return filtered;
    }

    private static string BuildSubRegionAddress(RealmData realm)
    {
        byte region = realm.Region == 0 ? (byte)1 : realm.Region;
        byte battlegroup = realm.Battlegroup == 0 ? (byte)1 : realm.Battlegroup;
        return $"{region}-{battlegroup}-0";
    }

    private static uint BuildRealmAddress(RealmData realm)
    {
        uint region = realm.Region == 0 ? 1u : realm.Region;
        uint battlegroup = realm.Battlegroup == 0 ? 1u : realm.Battlegroup;
        uint realmId = realm.Id & 0xFFFFu;
        return (region << 24) | (battlegroup << 16) | realmId;
    }

    private static byte[] BuildRealmListUpdatesJson(IReadOnlyList<RealmData> realms, uint clientBuild)
    {
        var buffer = new ArrayBufferWriter<byte>(Math.Max(256, realms.Count * 220));
        using var writer = new Utf8JsonWriter(buffer);

        writer.WriteStartObject();
        writer.WritePropertyName("updates");
        writer.WriteStartArray();

        for (int i = 0; i < realms.Count; i++)
        {
            RealmData realm = realms[i];
            uint realmAddress = BuildRealmAddress(realm);
            uint populationState = ResolvePopulationState(realm);
            uint realmFlags = ResolveRealmFlags(realm, clientBuild);
            uint cfgConfigsId = ResolveConfigId(realm.Icon);
            (uint major, uint minor, uint revision, uint build) = ResolveClientVersion(realm.Gamebuild, clientBuild);

            writer.WriteStartObject();
            writer.WriteNumber("wowRealmAddress", realmAddress);

            writer.WritePropertyName("update");
            writer.WriteStartObject();
            writer.WriteNumber("wowRealmAddress", realmAddress);
            writer.WriteNumber("cfgTimezonesID", 1u);
            writer.WriteNumber("populationState", populationState);
            writer.WriteNumber("cfgCategoriesID", realm.Timezone);

            writer.WritePropertyName("version");
            writer.WriteStartObject();
            writer.WriteNumber("versionMajor", major);
            writer.WriteNumber("versionMinor", minor);
            writer.WriteNumber("versionRevision", revision);
            writer.WriteNumber("versionBuild", build);
            writer.WriteEndObject();

            writer.WriteNumber("cfgRealmsID", realm.Id & 0xFFFFu);
            writer.WriteNumber("flags", realmFlags);
            writer.WriteString("name", string.IsNullOrWhiteSpace(realm.Name) ? "Adapter Realm" : realm.Name);
            writer.WriteNumber("cfgConfigsID", cfgConfigsId);
            writer.WriteNumber("cfgLanguagesID", 1u);
            writer.WriteEndObject();

            writer.WriteBoolean("deleting", false);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] BuildRealmCharacterCountListJson(IReadOnlyList<RealmData> realms)
    {
        var buffer = new ArrayBufferWriter<byte>(Math.Max(64, realms.Count * 40));
        using var writer = new Utf8JsonWriter(buffer);

        writer.WriteStartObject();
        writer.WritePropertyName("counts");
        writer.WriteStartArray();

        // We do not have per-account character counts on auth bridge stage; send zero counts.
        for (int i = 0; i < realms.Count; i++)
        {
            RealmData realm = realms[i];
            writer.WriteStartObject();
            writer.WriteNumber("wowRealmAddress", BuildRealmAddress(realm));
            writer.WriteNumber("count", 0u);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] BuildRealmListServerIpAddressesJson(RealmData realm)
    {
        string host = string.IsNullOrWhiteSpace(realm.Address) ? "127.0.0.1" : realm.Address.Trim();
        if (host.Contains(':') && !IPAddress.TryParse(host, out _))
        {
            // Normalize accidental host:port from DB.
            int sep = host.LastIndexOf(':');
            if (sep > 0)
            {
                host = host[..sep];
            }
        }

        uint family = host.Contains(':') ? 2u : 1u;

        var buffer = new ArrayBufferWriter<byte>(160);
        using var writer = new Utf8JsonWriter(buffer);

        writer.WriteStartObject();
        writer.WritePropertyName("families");
        writer.WriteStartArray();
        writer.WriteStartObject();
        writer.WriteNumber("family", family);
        writer.WritePropertyName("addresses");
        writer.WriteStartArray();
        writer.WriteStartObject();
        writer.WriteString("ip", host);
        writer.WriteNumber("port", realm.Port);
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }

    private static uint ResolvePopulationState(RealmData realm)
    {
        // Mirrors Trinity legacy-to-modern population mapping.
        if ((realm.Flag & 0x02) != 0)
        {
            return 0; // Offline
        }

        if (realm.AllowedSecurityLevel > 0)
        {
            return 7; // Locked
        }

        float population = ClampPopulation(realm.Population);

        if ((realm.Flag & 0x20) != 0)
        {
            return 5; // Recommended
        }

        if ((realm.Flag & 0x40) != 0)
        {
            return 4; // New
        }

        if ((realm.Flag & 0x80) != 0 || population > 0.95f)
        {
            return 6; // Full
        }

        if (population > 0.66f)
        {
            return 3; // High
        }

        if (population > 0.33f)
        {
            return 2; // Medium
        }

        return 1; // Low
    }

    private static uint ResolveRealmFlags(RealmData realm, uint clientBuild)
    {
        // Force compatibility in adapter mode: do not mark realms as VersionMismatch.
        _ = realm;
        _ = clientBuild;
        return 0u;
    }

    private static uint ResolveConfigId(byte realmIcon)
    {
        // Trinity Realm::ConfigIdByType[0..13] -> values 1..14.
        return realmIcon < 14 ? (uint)realmIcon + 1u : 1u;
    }

    private static (uint Major, uint Minor, uint Revision, uint Build) ResolveClientVersion(uint realmBuild, uint clientBuild)
    {
        // Keep realm version aligned with current retail client build to avoid incompatible realm state.
        _ = realmBuild;
        uint build = clientBuild;

        if (build >= 66000)
        {
            return (12, 0, 1, build);
        }

        if (build == 12340)
        {
            return (3, 3, 5, build);
        }

        // Trinity fallback for unknown build.
        return (6, 2, 4, build);
    }

    private static bool TryCompressPrefixedJson(
        ReadOnlySpan<byte> prefixUtf8,
        ReadOnlySpan<byte> jsonUtf8,
        out byte[] compressed)
    {
        compressed = Array.Empty<byte>();

        int uncompressedLength = prefixUtf8.Length + jsonUtf8.Length + 1; // include '\0' like Trinity compress(json.length()+1)
        byte[] rented = ArrayPool<byte>.Shared.Rent(uncompressedLength);

        try
        {
            Span<byte> uncompressed = rented.AsSpan(0, uncompressedLength);
            int offset = 0;
            prefixUtf8.CopyTo(uncompressed[offset..]);
            offset += prefixUtf8.Length;
            jsonUtf8.CopyTo(uncompressed[offset..]);
            offset += jsonUtf8.Length;
            uncompressed[offset] = 0;

            using var stream = new MemoryStream(capacity: Math.Max(64, uncompressedLength));
            // Reserve 4-byte uncompressed length prefix.
            stream.WriteByte(0);
            stream.WriteByte(0);
            stream.WriteByte(0);
            stream.WriteByte(0);

            using (var zlib = new ZLibStream(stream, CompressionLevel.Optimal, leaveOpen: true))
            {
                zlib.Write(uncompressed);
            }

            compressed = stream.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(compressed.AsSpan(0, sizeof(uint)), (uint)uncompressedLength);
            return true;
        }
        catch
        {
            compressed = Array.Empty<byte>();
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}

internal ref struct SpanPacketWriter
{
    private readonly IBufferWriter<byte> _writer;

    public SpanPacketWriter(IBufferWriter<byte> writer)
    {
        _writer = writer;
    }

    public bool TryWriteByte(byte value)
    {
        Span<byte> span = _writer.GetSpan(1);
        span[0] = value;
        _writer.Advance(1);
        return true;
    }

    public bool TryWriteUInt32(uint value)
    {
        Span<byte> span = _writer.GetSpan(sizeof(uint));
        BinaryPrimitives.WriteUInt32LittleEndian(span, value);
        _writer.Advance(sizeof(uint));
        return true;
    }

    public bool TryWriteSingle(float value)
    {
        Span<byte> span = _writer.GetSpan(sizeof(float));
        BinaryPrimitives.WriteSingleLittleEndian(span, value);
        _writer.Advance(sizeof(float));
        return true;
    }

    public bool TryWriteUtf8String16(string value)
    {
        value ??= string.Empty;
        int byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount > ushort.MaxValue)
        {
            return false;
        }

        Span<byte> lengthSpan = _writer.GetSpan(sizeof(ushort));
        BinaryPrimitives.WriteUInt16LittleEndian(lengthSpan, (ushort)byteCount);
        _writer.Advance(sizeof(ushort));

        if (byteCount == 0)
        {
            return true;
        }

        Span<byte> payloadSpan = _writer.GetSpan(byteCount);
        int written = Encoding.UTF8.GetBytes(value.AsSpan(), payloadSpan);
        if (written != byteCount)
        {
            return false;
        }

        _writer.Advance(byteCount);
        return true;
    }
}
