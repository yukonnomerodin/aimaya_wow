using System.Buffers;

namespace Adapter.WorldGateway;

internal static class PostAuthTranslationHelpers
{
    public static void ReorderFirstDeferredFrameAfterPrelude(
        ArrayBufferWriter<byte> bootstrapBuffer,
        List<string> stagedOpcodes,
        uint preludeOpcode)
    {
        if (bootstrapBuffer.WrittenCount <= 0)
        {
            return;
        }

        byte[] snapshot = bootstrapBuffer.WrittenMemory.ToArray();
        if (!RetailFrameCodec.TrySplitRetailWorldFrames(snapshot, out List<RetailFrameChunk> frames, out _))
        {
            return;
        }

        if (frames.Count < 2)
        {
            return;
        }

        int preludeFrameIndex = frames.FindIndex(frame => frame.Opcode == preludeOpcode);
        if (preludeFrameIndex <= 0)
        {
            return;
        }

        RetailFrameChunk firstFrame = frames[0];
        frames.RemoveAt(0);
        int insertIndex = Math.Min(preludeFrameIndex, frames.Count);
        frames.Insert(insertIndex, firstFrame);

        bootstrapBuffer.Clear();
        for (int i = 0; i < frames.Count; i++)
        {
            bootstrapBuffer.Write(frames[i].Frame);
        }

        if (stagedOpcodes.Count < 2)
        {
            return;
        }

        string preludeOpcodeToken = $"0x{preludeOpcode:X8}";
        int preludeOpcodeIndex = stagedOpcodes.IndexOf(preludeOpcodeToken);
        if (preludeOpcodeIndex <= 0)
        {
            return;
        }

        string firstStagedOpcode = stagedOpcodes[0];
        stagedOpcodes.RemoveAt(0);
        int stagedInsertIndex = Math.Min(preludeOpcodeIndex, stagedOpcodes.Count);
        stagedOpcodes.Insert(stagedInsertIndex, firstStagedOpcode);
    }

    public static bool TryBuildControlledUnlockEmptyCharEnumFrame(
        ReadOnlySpan<byte> acPayload,
        uint enumCharactersResultOpcode,
        out byte[] retailFrame)
    {
        retailFrame = Array.Empty<byte>();

        // AzerothCore 3.3.5a SMSG_CHAR_ENUM encodes char count in the first byte.
        // We only override the known empty-list case (count=0, payload length=1).
        if (acPayload.Length != 1 || acPayload[0] != 0)
        {
            return false;
        }

        retailFrame = RetailEmptyEnumCharactersResultBuilder.BuildFrame(enumCharactersResultOpcode);
        return true;
    }

    public static bool TryDecodeAcoreServerPacketSize(ReadOnlySpan<byte> header, out int packetSizeIncludingOpcode, out string error)
    {
        packetSizeIncludingOpcode = 0;
        error = string.Empty;

        if (header.Length == 4)
        {
            packetSizeIncludingOpcode = ((header[0] & 0x7F) << 8) | header[1];
        }
        else if (header.Length == 5)
        {
            packetSizeIncludingOpcode = ((header[0] & 0x7F) << 16) | (header[1] << 8) | header[2];
        }
        else
        {
            error = $"Unsupported AC server header length: {header.Length}.";
            return false;
        }

        if (packetSizeIncludingOpcode < 2)
        {
            error = $"Invalid AC server packet size field: {packetSizeIncludingOpcode}.";
            return false;
        }

        return true;
    }
}
