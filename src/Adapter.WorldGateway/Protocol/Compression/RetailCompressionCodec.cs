using ICSharpCode.SharpZipLib.Zip.Compression;
using System.IO.Compression;

namespace Adapter.WorldGateway;

internal static class RetailCompressionCodec
{
    public static bool TryCompress(
        ReadOnlySpan<byte> input,
        bool useRawDeflate,
        bool useStatefulRawDeflateSyncFlush,
        int rawDeflateLevel,
        StatefulRawDeflateSyncFlushCompressor? statefulCompressor,
        out byte[] output,
        out string? error)
    {
        if (useRawDeflate && useStatefulRawDeflateSyncFlush)
        {
            if (statefulCompressor is null)
            {
                output = Array.Empty<byte>();
                error = "Stateful raw-deflate compressor is not initialized.";
                return false;
            }

            return statefulCompressor.TryCompressSyncFlush(input, out output, out error);
        }

        return useRawDeflate
            ? TryCompressRawDeflate(input, rawDeflateLevel, out output, out error)
            : TryCompressZlibWrapped(input, out output, out error);
    }

    public static uint ComputeAdler32(uint seed, ReadOnlySpan<byte> data)
    {
        const uint ModAdler = 65521;
        uint a = seed & 0xFFFF;
        uint b = (seed >> 16) & 0xFFFF;

        for (int i = 0; i < data.Length; i++)
        {
            a += data[i];
            if (a >= ModAdler)
            {
                a -= ModAdler;
            }

            b += a;
            b %= ModAdler;
        }

        return (b << 16) | a;
    }

    public static int NormalizeDeflateLevel(int configuredLevel)
    {
        if (configuredLevel is >= 0 and <= 9)
        {
            return configuredLevel;
        }

        return Deflater.DEFAULT_COMPRESSION;
    }

    public static uint NormalizeChecksumSeed(long configuredSeed, uint fallbackSeed)
    {
        if (configuredSeed is >= 0 and <= uint.MaxValue)
        {
            return (uint)configuredSeed;
        }

        return fallbackSeed;
    }

    private static bool TryCompressZlibWrapped(ReadOnlySpan<byte> input, out byte[] output, out string? error)
    {
        output = Array.Empty<byte>();
        error = null;

        try
        {
            using var stream = new MemoryStream(input.Length + 32);
            using (var zlib = new ZLibStream(stream, CompressionLevel.Optimal, leaveOpen: true))
            {
                zlib.Write(input);
                zlib.Flush();
            }

            output = stream.ToArray();
            if (output.Length == 0)
            {
                error = "Zlib compression returned an empty payload.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            output = Array.Empty<byte>();
            error = ex.Message;
            return false;
        }
    }

    private static bool TryCompressRawDeflate(
        ReadOnlySpan<byte> input,
        int rawDeflateLevel,
        out byte[] output,
        out string? error)
    {
        output = Array.Empty<byte>();
        error = null;

        try
        {
            using var stream = new MemoryStream(input.Length + 32);
            var deflater = new Deflater(NormalizeDeflateLevel(rawDeflateLevel), noZlibHeaderOrFooter: true);
            byte[] inputArray = input.ToArray();
            deflater.SetInput(inputArray, 0, inputArray.Length);
            deflater.Finish();

            byte[] scratch = GC.AllocateUninitializedArray<byte>(8 * 1024);
            while (!deflater.IsFinished)
            {
                int produced = deflater.Deflate(scratch, 0, scratch.Length);
                if (produced <= 0)
                {
                    break;
                }

                stream.Write(scratch, 0, produced);
            }

            output = stream.ToArray();
            if (output.Length == 0)
            {
                error = "Raw deflate compression returned an empty payload.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            output = Array.Empty<byte>();
            error = ex.Message;
            return false;
        }
    }
}

internal sealed class StatefulRawDeflateSyncFlushCompressor : IDisposable
{
    private readonly Deflater _deflater;
    private readonly byte[] _scratch = GC.AllocateUninitializedArray<byte>(8 * 1024);
    private bool _disposed;

    public StatefulRawDeflateSyncFlushCompressor(int compressionLevel)
    {
        // Trinity initializes zlib with negative window bits (raw stream, no zlib header/footer).
        _deflater = new Deflater(RetailCompressionCodec.NormalizeDeflateLevel(compressionLevel), noZlibHeaderOrFooter: true);
    }

    public bool TryCompressSyncFlush(ReadOnlySpan<byte> input, out byte[] output, out string? error)
    {
        output = Array.Empty<byte>();
        error = null;

        if (_disposed)
        {
            error = "Stateful deflater is disposed.";
            return false;
        }

        try
        {
            using var stream = new MemoryStream(input.Length + 32);
            byte[] inputArray = input.ToArray();
            _deflater.SetInput(inputArray, 0, inputArray.Length);

            if (!DrainTo(stream, out error))
            {
                return false;
            }

            _deflater.Flush();
            if (!DrainTo(stream, out error))
            {
                return false;
            }

            output = stream.ToArray();
            if (output.Length == 0)
            {
                error = "Stateful raw-deflate returned an empty payload.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            output = Array.Empty<byte>();
            error = ex.Message;
            return false;
        }
    }

    public void Dispose()
    {
        _disposed = true;
    }

    private bool DrainTo(MemoryStream destination, out string? error)
    {
        error = null;
        int guard = 0;

        while (guard < 65536)
        {
            int produced = _deflater.Deflate(_scratch, 0, _scratch.Length);
            if (produced > 0)
            {
                destination.Write(_scratch, 0, produced);
                guard = 0;
                continue;
            }

            if (_deflater.IsNeedingInput)
            {
                return true;
            }

            guard++;
        }

        error = "Stateful raw-deflate drain exceeded guard limit.";
        return false;
    }
}
