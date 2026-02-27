namespace Adapter.WorldGateway;

internal static class AuthResponseFuzzMutationResolver
{
    public static AuthResponseFuzzMutation Resolve(
        bool enabled,
        string plan,
        int iteration,
        uint opcodeSweepStart,
        int opcodeSweepCount,
        out bool planRecognized)
    {
        if (!enabled)
        {
            planRecognized = true;
            return AuthResponseFuzzMutation.Disabled;
        }

        string normalizedPlan = string.IsNullOrWhiteSpace(plan)
            ? "M1-FUZZ-500"
            : plan.Trim();
        planRecognized = IsKnownPlan(normalizedPlan);
        if (!planRecognized)
        {
            return AuthResponseFuzzMutation.Disabled with
            {
                Enabled = true,
                Plan = normalizedPlan,
                Iteration = iteration,
                MutationLabel = "unknown_plan"
            };
        }

        int normalizedIteration = Math.Max(0, iteration);
        if (normalizedIteration == 0)
        {
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: 0,
                AccountDataPermutationVariant: -1,
                OpcodeOverride: null,
                UseShortRealmId: false,
                SwapExpansionAndBillingFlags: false,
                InsertPaddingU32AfterBitBlock: false,
                MutationLabel: "control_baseline");
        }

        if (normalizedIteration <= 32)
        {
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: normalizedIteration,
                AccountDataPermutationVariant: -1,
                OpcodeOverride: null,
                UseShortRealmId: false,
                SwapExpansionAndBillingFlags: false,
                InsertPaddingU32AfterBitBlock: false,
                MutationLabel: $"leading_zero_bits={normalizedIteration}");
        }

        if (normalizedIteration <= 100)
        {
            int permutationVariant = normalizedIteration - 33;
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: 0,
                AccountDataPermutationVariant: permutationVariant,
                OpcodeOverride: null,
                UseShortRealmId: false,
                SwapExpansionAndBillingFlags: false,
                InsertPaddingU32AfterBitBlock: false,
                MutationLabel: $"account_data_permutation_variant={permutationVariant}");
        }

        if (normalizedIteration <= 200)
        {
            uint opcodeOverride = opcodeSweepStart + (uint)(normalizedIteration - 100);
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: 0,
                AccountDataPermutationVariant: -1,
                OpcodeOverride: opcodeOverride,
                UseShortRealmId: false,
                SwapExpansionAndBillingFlags: false,
                InsertPaddingU32AfterBitBlock: false,
                MutationLabel: $"opcode_override=0x{opcodeOverride:X8}");
        }

        if (normalizedIteration <= 250)
        {
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: 0,
                AccountDataPermutationVariant: -1,
                OpcodeOverride: null,
                UseShortRealmId: true,
                SwapExpansionAndBillingFlags: false,
                InsertPaddingU32AfterBitBlock: false,
                MutationLabel: "short_realm_id_only");
        }

        if (normalizedIteration <= 300)
        {
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: 0,
                AccountDataPermutationVariant: -1,
                OpcodeOverride: null,
                UseShortRealmId: false,
                SwapExpansionAndBillingFlags: true,
                InsertPaddingU32AfterBitBlock: false,
                MutationLabel: "swap_expansion_and_billing_flags");
        }

        if (normalizedIteration <= 400)
        {
            return new AuthResponseFuzzMutation(
                Enabled: true,
                Plan: normalizedPlan,
                Iteration: normalizedIteration,
                LeadingZeroBits: 0,
                AccountDataPermutationVariant: -1,
                OpcodeOverride: null,
                UseShortRealmId: false,
                SwapExpansionAndBillingFlags: false,
                InsertPaddingU32AfterBitBlock: true,
                MutationLabel: "insert_padding_u32_after_bit_block");
        }

        int safeSweepCount = Math.Max(1, opcodeSweepCount);
        int sweepOffset = (normalizedIteration - 401) % safeSweepCount;
        uint fallbackOpcodeOverride = opcodeSweepStart + (uint)sweepOffset;
        return new AuthResponseFuzzMutation(
            Enabled: true,
            Plan: normalizedPlan,
            Iteration: normalizedIteration,
            LeadingZeroBits: 0,
            AccountDataPermutationVariant: -1,
            OpcodeOverride: fallbackOpcodeOverride,
            UseShortRealmId: false,
            SwapExpansionAndBillingFlags: false,
            InsertPaddingU32AfterBitBlock: false,
            MutationLabel: $"opcode_override_fallback=0x{fallbackOpcodeOverride:X8}");
    }

    private static bool IsKnownPlan(string plan)
    {
        return string.Equals(plan, "M1-FUZZ-500", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(plan, "M1-FUZZ-BATCH-01", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(plan, "BATCH-01", StringComparison.OrdinalIgnoreCase);
    }
}
