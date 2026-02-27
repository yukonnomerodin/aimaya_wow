namespace Adapter.WorldGateway;

internal static class RetailSetTimeZoneInformationBuilder
{
    public static byte[] BuildFrame(uint opcode, string timezone = "Etc/UTC")
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 48);
        payload.WriteBits((ulong)timezone.Length, 7);
        payload.WriteBits((ulong)timezone.Length, 7);
        payload.WriteBits((ulong)timezone.Length, 7);
        payload.FlushBits();

        payload.WriteAscii(timezone);
        payload.WriteAscii(timezone);
        payload.WriteAscii(timezone);

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }
}
