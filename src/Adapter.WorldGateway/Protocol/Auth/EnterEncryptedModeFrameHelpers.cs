using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class EnterEncryptedModeFrameHelpers
{
    public static bool TryPatchSignatureInFrame(
        byte[] retailFrame,
        string runtimeSignatureHex,
        bool includeRegionGroup,
        bool signatureFirst,
        out string? error)
    {
        error = null;

        if (string.IsNullOrWhiteSpace(runtimeSignatureHex))
        {
            error = "Runtime signature is empty.";
            return false;
        }

        byte[] runtimeSignature;
        try
        {
            runtimeSignature = Convert.FromHexString(runtimeSignatureHex.Trim());
        }
        catch (FormatException ex)
        {
            error = $"Runtime signature hex is invalid: {ex.Message}";
            return false;
        }

        if (runtimeSignature.Length != 64)
        {
            error = $"Runtime signature length is {runtimeSignature.Length}, expected 64 bytes.";
            return false;
        }

        if (!TryExtractPayloadFromFrame(retailFrame, out byte[] payload, out string? payloadError))
        {
            error = payloadError;
            return false;
        }

        int signatureOffset = includeRegionGroup
            ? (signatureFirst ? 0 : 4)
            : 0;

        if (signatureOffset + runtimeSignature.Length > payload.Length)
        {
            error =
                $"Golden payload is too short for signature patch. PayloadBytes={payload.Length}, SignatureOffset={signatureOffset}, SignatureBytes={runtimeSignature.Length}.";
            return false;
        }

        Buffer.BlockCopy(runtimeSignature, 0, payload, signatureOffset, runtimeSignature.Length);
        Buffer.BlockCopy(payload, 0, retailFrame, WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes, payload.Length);
        return true;
    }

    public static bool TryExtractPayloadFromFrame(byte[] retailFrame, out byte[] payload, out string? error)
    {
        payload = Array.Empty<byte>();
        error = null;

        if (retailFrame.Length < WorldGatewayProtocolConstants.RetailWorldFrameMinBytes)
        {
            error = $"Retail frame is too short: {retailFrame.Length}.";
            return false;
        }

        uint size = BinaryPrimitives.ReadUInt32LittleEndian(retailFrame.AsSpan(0, WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
        if (size < WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
        {
            error = $"Retail frame size is invalid: {size}.";
            return false;
        }

        int expectedFrameBytes = checked((int)size + WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes);
        if (retailFrame.Length != expectedFrameBytes)
        {
            error = $"Retail frame length mismatch. Actual={retailFrame.Length}, Expected={expectedFrameBytes}.";
            return false;
        }

        int payloadBytes = checked((int)size - WorldGatewayProtocolConstants.RetailWorldOpcodeBytes);
        payload = retailFrame.AsSpan(WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes, payloadBytes).ToArray();
        return true;
    }
}
