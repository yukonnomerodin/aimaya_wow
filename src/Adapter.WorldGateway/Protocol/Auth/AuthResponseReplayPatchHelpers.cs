using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class AuthResponseReplayPatchHelpers
{
    private const int OptionalBitsOffset = WorldGatewayProtocolConstants.AuthResponseReplayOptionalBitsOffset;
    private const byte SuccessInfoMask = WorldGatewayProtocolConstants.AuthResponseReplaySuccessInfoMask;
    private const byte WaitInfoMask = WorldGatewayProtocolConstants.AuthResponseReplayWaitInfoMask;
    private const byte SuccessInfoCurrentBuildMask = WorldGatewayProtocolConstants.AuthResponseReplaySuccessInfoCurrentBuildMask;
    private const uint CurrentBuildValue = WorldGatewayProtocolConstants.AuthResponseReplayCurrentBuildValue;
    private const int WaitInfoPayloadBytes = WorldGatewayProtocolConstants.AuthResponseReplayWaitInfoPayloadBytes;
    private const int SuccessInfoOffset = WorldGatewayProtocolConstants.AuthResponseReplaySuccessInfoOffset;
    private const int TopVirtualRealmAddressOffset = WorldGatewayProtocolConstants.AuthResponseReplayTopVirtualRealmAddressOffset;
    private const int ActiveExpansionLevelOffset = WorldGatewayProtocolConstants.AuthResponseReplayActiveExpansionLevelOffset;
    private const int AccountExpansionLevelOffset = WorldGatewayProtocolConstants.AuthResponseReplayAccountExpansionLevelOffset;
    private const int AvailableClassesCountOffset = WorldGatewayProtocolConstants.AuthResponseReplayAvailableClassesCountOffset;
    private const int ClassMatrixStartOffset = WorldGatewayProtocolConstants.AuthResponseReplayClassMatrixStartOffset;
    private const uint MaxAvailableClassesRows = WorldGatewayProtocolConstants.AuthResponseReplayMaxAvailableClassesRows;
    private const uint MaxClassRowsPerRace = WorldGatewayProtocolConstants.AuthResponseReplayMaxClassRowsPerRace;
    private const int TimeFieldOffset = WorldGatewayProtocolConstants.AuthResponseReplayTimeFieldOffset;

    public static bool TryPatchTopVirtualRealmAddressFromRuntimeRealm(
        ReadOnlySpan<byte> payload,
        uint acoreRealmId,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (payload.Length < TopVirtualRealmAddressOffset + sizeof(uint))
        {
            error = $"AUTH_RESPONSE replay payload too short for top VirtualRealmAddress patch: len={payload.Length}, required={TopVirtualRealmAddressOffset + sizeof(uint)}.";
            return false;
        }

        if ((payload[OptionalBitsOffset] & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        patchedPayload = payload.ToArray();
        uint runtimeRealmAddress = WorldGatewayProtocolConstants.BuildRetailVirtualRealmAddress(acoreRealmId);
        BinaryPrimitives.WriteUInt32LittleEndian(
            patchedPayload.AsSpan(TopVirtualRealmAddressOffset, sizeof(uint)),
            runtimeRealmAddress);
        return true;
    }

    public static bool TryPatchExpansionLevelsFromAcoreAccount(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> acPayload,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (payload.Length < AccountExpansionLevelOffset + sizeof(byte))
        {
            error = $"AUTH_RESPONSE replay payload too short for expansion-level patch: len={payload.Length}, required={AccountExpansionLevelOffset + sizeof(byte)}.";
            return false;
        }

        if ((payload[OptionalBitsOffset] & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        byte accountExpansion = ResolveAcoreAccountExpansionLevel(acPayload);
        patchedPayload = payload.ToArray();
        patchedPayload[ActiveExpansionLevelOffset] = accountExpansion;
        patchedPayload[AccountExpansionLevelOffset] = accountExpansion;
        return true;
    }

    public static bool TryPatchCurrentBuildPresent(
        ReadOnlySpan<byte> payload,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (!TryLocateSuccessInfoOptionalFlagsOffset(
                payload,
                out int optionalFlagsOffset,
                out error))
        {
            return false;
        }

        int currentBuildOffset = optionalFlagsOffset + 1;
        bool currentBuildPresent = (payload[optionalFlagsOffset] & SuccessInfoCurrentBuildMask) != 0;

        if (currentBuildPresent)
        {
            if (currentBuildOffset + sizeof(uint) > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated at CurrentBuild field: offset={currentBuildOffset}, len={payload.Length}.";
                return false;
            }

            patchedPayload = payload.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(
                patchedPayload.AsSpan(currentBuildOffset, sizeof(uint)),
                CurrentBuildValue);
            return true;
        }

        patchedPayload = GC.AllocateUninitializedArray<byte>(payload.Length + sizeof(uint));

        payload[..(optionalFlagsOffset + 1)].CopyTo(patchedPayload.AsSpan(0, optionalFlagsOffset + 1));
        patchedPayload[optionalFlagsOffset] = (byte)(patchedPayload[optionalFlagsOffset] | SuccessInfoCurrentBuildMask);
        BinaryPrimitives.WriteUInt32LittleEndian(
            patchedPayload.AsSpan(currentBuildOffset, sizeof(uint)),
            CurrentBuildValue);
        payload[currentBuildOffset..].CopyTo(patchedPayload.AsSpan(currentBuildOffset + sizeof(uint)));
        return true;
    }

    public static bool TryPatchWaitInfoPresent(
        ReadOnlySpan<byte> payload,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (payload.Length <= OptionalBitsOffset)
        {
            error = $"AUTH_RESPONSE replay payload too short for top-level optional bits patch: len={payload.Length}, required>{OptionalBitsOffset}.";
            return false;
        }

        byte optionalBits = payload[OptionalBitsOffset];
        if ((optionalBits & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        if ((optionalBits & WaitInfoMask) != 0)
        {
            patchedPayload = payload.ToArray();
            return true;
        }

        patchedPayload = GC.AllocateUninitializedArray<byte>(payload.Length + WaitInfoPayloadBytes);
        payload.CopyTo(patchedPayload);
        patchedPayload[OptionalBitsOffset] =
            (byte)(patchedPayload[OptionalBitsOffset] | WaitInfoMask);
        patchedPayload.AsSpan(payload.Length, WaitInfoPayloadBytes).Clear();
        return true;
    }

    public static bool TryPatchVirtualRealmEntryFromRuntimeRealm(
        ReadOnlySpan<byte> payload,
        uint acoreRealmId,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (!TryLocateSuccessInfoOptionalFlagsOffset(
                payload,
                out int optionalFlagsOffset,
                out error))
        {
            return false;
        }

        int cursor = optionalFlagsOffset + 1;
        bool currentBuildPresent = (payload[optionalFlagsOffset] & SuccessInfoCurrentBuildMask) != 0;
        if (currentBuildPresent)
        {
            if (cursor + sizeof(uint) > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated at CurrentBuild field: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            cursor += sizeof(uint);
        }

        // GameTimeInfo fixed fields + flushed optional bits byte.
        const int GameTimeFixedBytes = WorldGatewayProtocolConstants.AuthResponseReplayGameTimeFixedBytes;
        const int GameTimeFlagsBytes = WorldGatewayProtocolConstants.AuthResponseReplayGameTimeFlagsBytes;
        if (cursor + GameTimeFixedBytes + GameTimeFlagsBytes > payload.Length)
        {
            error = $"AUTH_RESPONSE replay payload truncated at GameTimeInfo block: cursor={cursor}, len={payload.Length}.";
            return false;
        }

        cursor += GameTimeFixedBytes + GameTimeFlagsBytes;

        if (cursor + sizeof(uint) > payload.Length)
        {
            error = $"AUTH_RESPONSE replay payload truncated before VirtualRealmInfo.RealmAddress: cursor={cursor}, len={payload.Length}.";
            return false;
        }

        patchedPayload = payload.ToArray();
        uint runtimeRealmAddress = WorldGatewayProtocolConstants.BuildRetailVirtualRealmAddress(acoreRealmId);
        BinaryPrimitives.WriteUInt32LittleEndian(
            patchedPayload.AsSpan(cursor, sizeof(uint)),
            runtimeRealmAddress);

        return true;
    }

    public static bool TryPatchClassMatrixCardinalityToRuntimeSubset(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> acPayload,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (payload.Length < ClassMatrixStartOffset)
        {
            error = $"AUTH_RESPONSE replay payload too short for class-matrix cardinality patch: len={payload.Length}, required>={ClassMatrixStartOffset}.";
            return false;
        }

        if ((payload[OptionalBitsOffset] & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        if (payload.Length < AvailableClassesCountOffset + sizeof(uint))
        {
            error = $"AUTH_RESPONSE replay payload too short for AvailableClasses count: len={payload.Length}, required={AvailableClassesCountOffset + sizeof(uint)}.";
            return false;
        }

        uint availableClassesCount = BinaryPrimitives.ReadUInt32LittleEndian(
            payload.Slice(AvailableClassesCountOffset, sizeof(uint)));
        if (availableClassesCount > MaxAvailableClassesRows)
        {
            error = $"AUTH_RESPONSE replay payload AvailableClasses count is out of range: {availableClassesCount}.";
            return false;
        }

        byte accountExpansion = ResolveAcoreAccountExpansionLevel(acPayload);
        int cursor = ClassMatrixStartOffset;
        var rewrittenMatrix = new List<byte>(Math.Max(256, payload.Length - ClassMatrixStartOffset));
        uint keptRaceRows = 0;

        for (uint raceIndex = 0; raceIndex < availableClassesCount; raceIndex++)
        {
            if (cursor + 1 + sizeof(uint) > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated before race row {raceIndex}: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            byte raceId = payload[cursor];
            uint classCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(cursor + 1, sizeof(uint)));
            if (classCount > MaxClassRowsPerRace)
            {
                error = $"AUTH_RESPONSE replay payload class count is out of range at race row {raceIndex}: {classCount}.";
                return false;
            }

            cursor += 1 + sizeof(uint);

            int raceRowStart = rewrittenMatrix.Count;
            rewrittenMatrix.Add(raceId);
            rewrittenMatrix.Add(0);
            rewrittenMatrix.Add(0);
            rewrittenMatrix.Add(0);
            rewrittenMatrix.Add(0);

            uint keptClassRows = 0;
            for (uint classIndex = 0; classIndex < classCount; classIndex++)
            {
                if (cursor + 4 > payload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated at race row {raceIndex}, class row {classIndex}: cursor={cursor}, len={payload.Length}.";
                    return false;
                }

                byte classId = payload[cursor];
                if (IsClassAllowedForExpansion(classId, accountExpansion))
                {
                    rewrittenMatrix.Add(payload[cursor]);
                    rewrittenMatrix.Add(payload[cursor + 1]);
                    rewrittenMatrix.Add(payload[cursor + 2]);
                    rewrittenMatrix.Add(payload[cursor + 3]);
                    keptClassRows++;
                }

                cursor += 4;
            }

            if (keptClassRows == 0)
            {
                rewrittenMatrix.RemoveRange(raceRowStart, rewrittenMatrix.Count - raceRowStart);
                continue;
            }

            rewrittenMatrix[raceRowStart + 1] = (byte)(keptClassRows & 0xFFu);
            rewrittenMatrix[raceRowStart + 2] = (byte)((keptClassRows >> 8) & 0xFFu);
            rewrittenMatrix[raceRowStart + 3] = (byte)((keptClassRows >> 16) & 0xFFu);
            rewrittenMatrix[raceRowStart + 4] = (byte)((keptClassRows >> 24) & 0xFFu);
            keptRaceRows++;
        }

        if (cursor > payload.Length)
        {
            error = $"AUTH_RESPONSE replay payload class-matrix cursor overrun: cursor={cursor}, len={payload.Length}.";
            return false;
        }

        int suffixLength = payload.Length - cursor;
        patchedPayload = GC.AllocateUninitializedArray<byte>(
            ClassMatrixStartOffset + rewrittenMatrix.Count + suffixLength);

        payload[..ClassMatrixStartOffset].CopyTo(patchedPayload);
        BinaryPrimitives.WriteUInt32LittleEndian(
            patchedPayload.AsSpan(AvailableClassesCountOffset, sizeof(uint)),
            keptRaceRows);

        for (int i = 0; i < rewrittenMatrix.Count; i++)
        {
            patchedPayload[ClassMatrixStartOffset + i] = rewrittenMatrix[i];
        }

        payload[cursor..].CopyTo(
            patchedPayload.AsSpan(ClassMatrixStartOffset + rewrittenMatrix.Count, suffixLength));

        return true;
    }

    public static bool TryPatchClassMatrixExpansionTripletsFromAcoreAccount(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> acPayload,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (payload.Length < ClassMatrixStartOffset)
        {
            error = $"AUTH_RESPONSE replay payload too short for class-matrix patch: len={payload.Length}, required>={ClassMatrixStartOffset}.";
            return false;
        }

        if ((payload[OptionalBitsOffset] & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        if (payload.Length < AvailableClassesCountOffset + sizeof(uint))
        {
            error = $"AUTH_RESPONSE replay payload too short for AvailableClasses count: len={payload.Length}, required={AvailableClassesCountOffset + sizeof(uint)}.";
            return false;
        }

        uint availableClassesCount = BinaryPrimitives.ReadUInt32LittleEndian(
            payload.Slice(AvailableClassesCountOffset, sizeof(uint)));
        if (availableClassesCount > MaxAvailableClassesRows)
        {
            error = $"AUTH_RESPONSE replay payload AvailableClasses count is out of range: {availableClassesCount}.";
            return false;
        }

        byte accountExpansion = ResolveAcoreAccountExpansionLevel(acPayload);
        patchedPayload = payload.ToArray();

        int cursor = ClassMatrixStartOffset;
        for (uint raceIndex = 0; raceIndex < availableClassesCount; raceIndex++)
        {
            if (cursor + 1 + sizeof(uint) > patchedPayload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated before race row {raceIndex}: cursor={cursor}, len={patchedPayload.Length}.";
                return false;
            }

            uint classCount = BinaryPrimitives.ReadUInt32LittleEndian(
                patchedPayload.AsSpan(cursor + 1, sizeof(uint)));
            if (classCount > MaxClassRowsPerRace)
            {
                error = $"AUTH_RESPONSE replay payload class count is out of range at race row {raceIndex}: {classCount}.";
                return false;
            }

            cursor += 1 + sizeof(uint);

            for (uint classIndex = 0; classIndex < classCount; classIndex++)
            {
                if (cursor + 4 > patchedPayload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated at race row {raceIndex}, class row {classIndex}: cursor={cursor}, len={patchedPayload.Length}.";
                    return false;
                }

                patchedPayload[cursor + 1] = accountExpansion;
                patchedPayload[cursor + 2] = accountExpansion;
                patchedPayload[cursor + 3] = accountExpansion;
                cursor += 4;
            }
        }

        return true;
    }

    public static bool TryPatchTimeUnixNow(
        ReadOnlySpan<byte> payload,
        out byte[] patchedPayload,
        out string? error)
    {
        patchedPayload = Array.Empty<byte>();
        error = null;

        if (payload.Length < TimeFieldOffset + sizeof(int))
        {
            error = $"AUTH_RESPONSE replay payload too short for time patch: len={payload.Length}, required={TimeFieldOffset + sizeof(int)}.";
            return false;
        }

        if ((payload[OptionalBitsOffset] & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        patchedPayload = payload.ToArray();
        int unixNow = checked((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        BinaryPrimitives.WriteInt32LittleEndian(
            patchedPayload.AsSpan(TimeFieldOffset, sizeof(int)),
            unixNow);
        return true;
    }

    private static bool TryLocateSuccessInfoOptionalFlagsOffset(
        ReadOnlySpan<byte> payload,
        out int optionalFlagsOffset,
        out string? error)
    {
        optionalFlagsOffset = 0;
        error = null;

        if (payload.Length < ClassMatrixStartOffset)
        {
            error = $"AUTH_RESPONSE replay payload too short for SuccessInfo optional-flags scan: len={payload.Length}, required>={ClassMatrixStartOffset}.";
            return false;
        }

        if ((payload[OptionalBitsOffset] & SuccessInfoMask) == 0)
        {
            error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {OptionalBitsOffset}.";
            return false;
        }

        if (payload.Length < AvailableClassesCountOffset + sizeof(uint))
        {
            error = $"AUTH_RESPONSE replay payload too short for AvailableClasses count: len={payload.Length}, required={AvailableClassesCountOffset + sizeof(uint)}.";
            return false;
        }

        uint availableClassesCount = BinaryPrimitives.ReadUInt32LittleEndian(
            payload.Slice(AvailableClassesCountOffset, sizeof(uint)));
        if (availableClassesCount > MaxAvailableClassesRows)
        {
            error = $"AUTH_RESPONSE replay payload AvailableClasses count is out of range: {availableClassesCount}.";
            return false;
        }

        int cursor = ClassMatrixStartOffset;
        for (uint raceIndex = 0; raceIndex < availableClassesCount; raceIndex++)
        {
            if (cursor + 1 + sizeof(uint) > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated before race row {raceIndex}: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            uint classCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(cursor + 1, sizeof(uint)));
            if (classCount > MaxClassRowsPerRace)
            {
                error = $"AUTH_RESPONSE replay payload class count is out of range at race row {raceIndex}: {classCount}.";
                return false;
            }

            cursor += 1 + sizeof(uint);
            int classBytes = checked((int)classCount * 4);
            if (cursor + classBytes > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated at race row {raceIndex}: cursor={cursor}, classBytes={classBytes}, len={payload.Length}.";
                return false;
            }

            cursor += classBytes;
        }

        if (cursor + 1 > payload.Length)
        {
            error = $"AUTH_RESPONSE replay payload truncated at SuccessInfo optional flags byte: cursor={cursor}, len={payload.Length}.";
            return false;
        }

        optionalFlagsOffset = cursor;
        return true;
    }

    private static byte ResolveAcoreAccountExpansionLevel(ReadOnlySpan<byte> acPayload)
    {
        const byte ExpansionTww = 10;
        const byte ExpansionWotlk = 2;

        byte accountExpansion = acPayload.Length >= 11
            ? (byte)Math.Clamp(acPayload[10], (byte)0, ExpansionTww)
            : ExpansionWotlk;
        if (accountExpansion == 0)
        {
            accountExpansion = ExpansionWotlk;
        }

        return accountExpansion;
    }

    private static bool IsClassAllowedForExpansion(byte classId, byte accountExpansion)
    {
        return classId switch
        {
            1 or 2 or 3 or 4 or 5 or 6 or 7 or 8 or 9 or 11 => true, // Vanilla/WotLK-era classes
            10 => accountExpansion >= 5, // Monk (MoP)
            12 => accountExpansion >= 6, // Demon Hunter (Legion)
            13 => accountExpansion >= 10, // Evoker (Dragonflight+)
            _ => false
        };
    }

}
