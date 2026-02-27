namespace Adapter.WorldGateway;

internal static class DbParityGateEvaluator
{
    public static DbParityGateResult Evaluate(
        RetailAuthSessionFrame retailFrame,
        AcoreSessionMaterial account,
        int acoreSessionKeyBytes,
        uint acoreRealmId,
        uint acoreClientBuild)
    {
        const string expected = "account/session/build flags are valid before AUTH_SESSION protocol rewrite";

        if (retailFrame.AccountId <= 0)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "missing_account_id",
                Expected: expected,
                Actual: "retail accountId <= 0");
        }

        if (retailFrame.AccountId != account.AccountId)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "account_binding_mismatch",
                Expected: expected,
                Actual: $"retail accountId={retailFrame.AccountId}, db accountId={account.AccountId}");
        }

        if (string.IsNullOrWhiteSpace(account.AccountName))
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "empty_account_name",
                Expected: expected,
                Actual: "db username is empty");
        }

        if (account.SessionKey.Length != acoreSessionKeyBytes)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "session_key_length_mismatch",
                Expected: expected,
                Actual: $"session_key bytes={account.SessionKey.Length}, required={acoreSessionKeyBytes}");
        }

        if (account.Locked)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "account_locked",
                Expected: expected,
                Actual: "db account.locked=1");
        }

        if (account.Expansion < 2)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "expansion_flag_too_low",
                Expected: expected,
                Actual: $"db expansion={account.Expansion}, required>=2 for 3.3.5a");
        }

        if (acoreRealmId == 0)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "invalid_realm_id",
                Expected: expected,
                Actual: "AcoreRealmId=0");
        }

        if (acoreClientBuild == 0)
        {
            return new DbParityGateResult(
                Passed: false,
                FailureReason: "invalid_acore_client_build",
                Expected: expected,
                Actual: $"AcoreClientBuild={acoreClientBuild}");
        }

        return new DbParityGateResult(
            Passed: true,
            FailureReason: "none",
            Expected: expected,
            Actual: $"ok: accountId={account.AccountId}, expansion={account.Expansion}, locked={account.Locked}, acore_build={acoreClientBuild}");
    }
}
