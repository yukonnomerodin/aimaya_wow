namespace Adapter.WorldGateway;

internal static class RetailAuthSequencePreludeBuilder
{
    public static byte[] BuildFrame(uint opcode, ReadOnlySpan<byte> payloadBytes)
    {
        if (payloadBytes.Length != 4)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadBytes), "Retail prelude payload must be exactly 4 bytes.");
        }

        Span<byte> payload = stackalloc byte[4];
        payloadBytes.CopyTo(payload);
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload);
    }
}
