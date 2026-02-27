using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class AuthResponseFrameBuilder
{
    public static bool TryBuildRetailAuthResponseFromAcore(
        ReadOnlySpan<byte> acPayload,
        bool probeResultOnly,
        uint probeResultOnlyCode,
        bool probeMinimalSuccessNoAccountData,
        bool probeTwwAccountDataProfile,
        bool probeTwwAddResultPrefix,
        bool probeForceWaitInfoPresent,
        bool probeForceCurrentBuildPresent,
        int probeAuthResponseAvailableClassesCardinality,
        int probeAuthResponseTwwClassMatrixRows,
        bool probeAuthResponseTwwUseAcoreExpansionLevels,
        AuthResponseFuzzMutation authResponseFuzzMutation,
        uint retailAuthResponseOpcode,
        uint acoreRealmId,
        uint authResponseReplayCurrentBuildValue,
        out byte[] retailFrame,
        out string? error)
    {
        retailFrame = Array.Empty<byte>();
        error = null;

        if (acPayload.IsEmpty)
        {
            error = "Acore SMSG_AUTH_RESPONSE payload is empty.";
            return false;
        }

        if (probeResultOnly)
        {
            // M1-PROBE-067 isolation: send bare minimum AUTH_RESPONSE body to separate
            // crypto-framing faults from account-data schema faults.
            var resultOnlyPayload = new BitPackedBufferWriter(initialCapacity: 8);
            resultOnlyPayload.WriteUInt32LE(probeResultOnlyCode);
            retailFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(retailAuthResponseOpcode, resultOnlyPayload.WrittenSpan);
            return true;
        }

        if (probeTwwAccountDataProfile)
        {
            retailFrame = BuildRetailAuthResponseTwwAccountDataProbeFrame(
                acPayload,
                acoreRealmId,
                retailAuthResponseOpcode,
                probeTwwAddResultPrefix,
                probeAuthResponseAvailableClassesCardinality,
                probeAuthResponseTwwClassMatrixRows,
                probeAuthResponseTwwUseAcoreExpansionLevels,
                authResponseFuzzMutation);
            return true;
        }

        const byte AuthOk = 0x0C;
        const byte AuthWaitQueue = 0x1B;
        const byte WotlkExpansion = 2;

        byte acResult = acPayload[0];
        bool isAuthOk = acResult == AuthOk || probeMinimalSuccessNoAccountData;
        bool isWaitQueue = !probeMinimalSuccessNoAccountData && acResult == AuthWaitQueue;
        bool hasSuccessInfo = !probeMinimalSuccessNoAccountData && (isAuthOk || isWaitQueue);
        // Match Trinity behavior: WaitInfo is present only for queued logins.
        bool hasWaitInfo = !probeMinimalSuccessNoAccountData && isWaitQueue;
        if (probeForceWaitInfoPresent && hasSuccessInfo)
        {
            hasWaitInfo = true;
        }

        uint retailResult = hasSuccessInfo
            ? 0u // ERROR_OK
            : 3u; // ERROR_DENIED

        var payload = new BitPackedBufferWriter(initialCapacity: 128);
        payload.WriteUInt32LE(retailResult);

        payload.WriteBit(hasSuccessInfo);
        payload.WriteBit(hasWaitInfo);
        payload.FlushBits();

        uint billingTimeRemaining = acPayload.Length >= 5 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(1, 4)) : 0u;
        uint billingTimeRested = acPayload.Length >= 10 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(6, 4)) : 0u;
        byte accountExpansion = acPayload.Length >= 11
            ? (byte)Math.Clamp(acPayload[10], (byte)0, WotlkExpansion)
            : WotlkExpansion;
        if (accountExpansion == 0)
        {
            accountExpansion = WotlkExpansion;
        }

        uint waitCount = acPayload.Length >= 15 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(11, 4)) : 0u;
        bool hasFcm = acPayload.Length >= 16 && acPayload[15] != 0;

        if (hasSuccessInfo)
        {
            // AuthSuccessInfo (TrinityCore serialization order)
            uint virtualRealmAddress = WorldGatewayProtocolConstants.BuildRetailVirtualRealmAddress(1u);
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            payload.WriteUInt32LE(virtualRealmAddress); // VirtualRealmAddress
            payload.WriteUInt32LE(1); // VirtualRealms count
            payload.WriteUInt32LE(billingTimeRested); // TimeRested
            payload.WriteByte(accountExpansion); // ActiveExpansionLevel
            payload.WriteByte(accountExpansion); // AccountExpansionLevel
            payload.WriteUInt32LE(0); // TimeSecondsUntilPCKick
            payload.WriteUInt32LE(1); // AvailableClasses count
            payload.WriteUInt32LE(0); // Templates count
            payload.WriteUInt32LE(0); // CurrencyID
            payload.WriteInt64LE(now); // Time (Timestamp<int64>)

            // Minimal race/class availability set (Human/Warrior) for client bootstrap.
            payload.WriteByte(1); // RaceID
            payload.WriteUInt32LE(1); // Classes count
            payload.WriteByte(1); // ClassID
            payload.WriteByte(accountExpansion); // ActiveExpansionLevel
            payload.WriteByte(accountExpansion); // AccountExpansionLevel
            payload.WriteByte(0); // MinActiveExpansionLevel

            // Optional bits in AuthSuccessInfo
            bool currentBuildPresent = probeForceCurrentBuildPresent;
            payload.WriteBit(false); // IsExpansionTrial
            payload.WriteBit(false); // ForceCharacterTemplate
            payload.WriteBit(false); // NumPlayersHorde
            payload.WriteBit(false); // NumPlayersAlliance
            payload.WriteBit(false); // ExpansionTrialExpiration
            payload.WriteBit(currentBuildPresent); // CurrentBuild
            payload.FlushBits();

            if (currentBuildPresent)
            {
                payload.WriteUInt32LE(authResponseReplayCurrentBuildValue); // Retail build for CurrentBuild optional field probe.
            }

            // GameTime
            payload.WriteUInt32LE(0); // BillingType
            payload.WriteUInt32LE(billingTimeRemaining); // MinutesRemaining (best-effort mapping)
            payload.WriteUInt32LE(0); // RealBillingType
            payload.WriteBit(false); // IsInIGR
            payload.WriteBit(false); // IsPaidForByIGR
            payload.WriteBit(false); // IsCAISEnabled
            payload.FlushBits();

            // Single VirtualRealmInfo
            const string realmName = "AzerothCore";
            payload.WriteUInt32LE(virtualRealmAddress);
            payload.WriteBit(true);  // IsLocal
            payload.WriteBit(false); // IsInternalRealm
            payload.WriteBits((ulong)realmName.Length, 8); // RealmNameActual length
            payload.WriteBits((ulong)realmName.Length, 8); // RealmNameNormalized length
            payload.FlushBits();
            payload.WriteAscii(realmName);
            payload.WriteAscii(realmName);
        }

        if (hasWaitInfo)
        {
            payload.WriteUInt32LE(waitCount); // WaitCount
            payload.WriteUInt32LE(0); // WaitTime
            payload.WriteByte(0); // AllowedFactionGroupForCharacterCreate
            payload.WriteBit(hasFcm); // HasFCM
            payload.WriteBit(false); // CanCreateOnlyIfExisting
            payload.FlushBits();
        }

        retailFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(retailAuthResponseOpcode, payload.WrittenSpan);
        return true;
    }

    private static byte[] BuildRetailAuthResponseTwwAccountDataProbeFrame(
        ReadOnlySpan<byte> acPayload,
        uint acoreRealmId,
        uint retailAuthResponseOpcode,
        bool includeResultPrefix,
        int availableClassesCardinality,
        int trinityClassMatrixRows,
        bool useAcoreExpansionLevels,
        AuthResponseFuzzMutation authResponseFuzzMutation)
    {
        uint billingTimeRemaining = acPayload.Length >= 5 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(1, 4)) : 0u;
        uint billingTimeRested = acPayload.Length >= 10 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(6, 4)) : 0u;
        uint virtualRealmAddress = WorldGatewayProtocolConstants.BuildRetailVirtualRealmAddress(acoreRealmId);
        const byte ExpansionTww = 10;
        const byte ExpansionWotlk = 2;
        const string RealmName = "AIMAYA";
        long nowUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte topExpansionLevel = ExpansionTww;
        if (useAcoreExpansionLevels)
        {
            byte acoreExpansion = acPayload.Length >= 11
                ? (byte)Math.Clamp(acPayload[10], (byte)0, ExpansionTww)
                : ExpansionWotlk;
            if (acoreExpansion == 0)
            {
                acoreExpansion = ExpansionWotlk;
            }

            topExpansionLevel = acoreExpansion;
        }

        // TWW probe profile aligned to Trinity AuthResponse envelope:
        // Result(uint32) + Optional(SuccessInfo/WaitInfo) bits + FlushBits + SuccessInfo payload.
        var payload = new BitPackedBufferWriter(initialCapacity: 192);
        if (includeResultPrefix)
        {
            payload.WriteUInt32LE(0); // Legacy probe knob; disabled for strict profile runs.
        }

        payload.WriteUInt32LE(0); // ERROR_OK

        if (authResponseFuzzMutation.Enabled && authResponseFuzzMutation.LeadingZeroBits > 0)
        {
            for (int bit = 0; bit < authResponseFuzzMutation.LeadingZeroBits; bit++)
            {
                payload.WriteBit(false);
            }
        }

        payload.WriteBit(true);  // SuccessInfo present
        payload.WriteBit(false); // WaitInfo absent
        payload.FlushBits();

        if (authResponseFuzzMutation.Enabled && authResponseFuzzMutation.InsertPaddingU32AfterBitBlock)
        {
            payload.WriteUInt32LE(0);
        }

        // AuthSuccessInfo (serialization order mirrors TrinityCore master branch)
        List<(byte RaceId, byte[] ClassIds)> raceClassMatrix;
        if (trinityClassMatrixRows > 0)
        {
            raceClassMatrix = AuthResponseClassMatrixHelpers.BuildLegacyClassMatrixPrefix(trinityClassMatrixRows);
        }
        else
        {
            int normalizedCardinality = Math.Clamp(availableClassesCardinality, 1, 13);
            byte[] twwClassIds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
            raceClassMatrix = new List<(byte RaceId, byte[] ClassIds)>(1)
            {
                ((byte)1, twwClassIds.AsSpan(0, normalizedCardinality).ToArray())
            };
        }

        payload.WriteUInt32LE(virtualRealmAddress); // VirtualRealmAddress
        payload.WriteUInt32LE(1); // VirtualRealms size
        payload.WriteUInt32LE(billingTimeRested); // TimeRested
        payload.WriteByte(topExpansionLevel); // ActiveExpansionLevel
        payload.WriteByte(topExpansionLevel); // AccountExpansionLevel
        payload.WriteUInt32LE(0); // TimeSecondsUntilPCKick
        payload.WriteUInt32LE((uint)raceClassMatrix.Count); // AvailableClasses size
        payload.WriteUInt32LE(0); // Templates size
        payload.WriteUInt32LE(0); // CurrencyID
        payload.WriteInt64LE(nowUnixSeconds); // Time

        for (int raceIndex = 0; raceIndex < raceClassMatrix.Count; raceIndex++)
        {
            (byte raceId, byte[] classIds) = raceClassMatrix[raceIndex];
            payload.WriteByte(raceId);
            payload.WriteUInt32LE((uint)classIds.Length);
            for (int classIndex = 0; classIndex < classIds.Length; classIndex++)
            {
                byte classId = classIds[classIndex];
                payload.WriteByte(classId);
                if (trinityClassMatrixRows > 0)
                {
                    (byte activeExpansion, byte accountExpansion, byte minActiveExpansion) =
                        AuthResponseClassMatrixHelpers.GetLegacyClassExpansionRequirement(classId);
                    payload.WriteByte(activeExpansion);
                    payload.WriteByte(accountExpansion);
                    payload.WriteByte(minActiveExpansion);
                }
                else
                {
                    payload.WriteByte(ExpansionTww); // ActiveExpansionLevel
                    payload.WriteByte(ExpansionTww); // AccountExpansionLevel
                    payload.WriteByte(0); // MinActiveExpansionLevel
                }
            }
        }

        // SuccessInfo optional flags
        payload.WriteBit(false); // IsExpansionTrial
        payload.WriteBit(false); // ForceCharacterTemplate
        payload.WriteBit(false); // NumPlayersHorde present
        payload.WriteBit(false); // NumPlayersAlliance present
        payload.WriteBit(false); // ExpansionTrialExpiration present
        payload.WriteBit(false); // CurrentBuild present
        payload.FlushBits();

        // GameTimeInfo
        payload.WriteUInt32LE(0); // BillingType
        payload.WriteUInt32LE(billingTimeRemaining); // MinutesRemaining
        payload.WriteUInt32LE(0); // RealBillingType
        payload.WriteBit(false); // IsInIGR
        payload.WriteBit(false); // IsPaidForByIGR
        payload.WriteBit(false); // IsCAISEnabled
        payload.FlushBits();

        // VirtualRealmInfo (single entry)
        payload.WriteUInt32LE(virtualRealmAddress); // RealmAddress
        payload.WriteBit(true);  // IsLocal
        payload.WriteBit(false); // IsInternalRealm
        payload.WriteBits((ulong)RealmName.Length, 8); // RealmNameActual length
        payload.WriteBits((ulong)RealmName.Length, 8); // RealmNameNormalized length
        payload.FlushBits();
        payload.WriteAscii(RealmName); // RealmNameActual
        payload.WriteAscii(RealmName); // RealmNameNormalized

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(retailAuthResponseOpcode, payload.WrittenSpan);
    }
}
