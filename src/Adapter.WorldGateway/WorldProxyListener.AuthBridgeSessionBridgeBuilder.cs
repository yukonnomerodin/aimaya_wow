using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using MySqlConnector;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<AcoreAuthSessionBridgeResult?> TryBuildAcoreAuthSessionFrameAsync(
        uint authSeed,
        RetailAuthSessionFrame retailFrame,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        using var dbCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        dbCts.CancelAfter(_options.AuthBridgeDbTimeoutMs);
        CancellationToken dbToken = dbCts.Token;

        try
        {
            int accountId = retailFrame.AccountId;
            string accountIdSource = "retail_payload";
            if (accountId <= 0)
            {
                (accountId, accountIdSource) = await ResolveMissingRetailAccountIdAsync(dbToken).ConfigureAwait(false);
                if (accountId > 0)
                {
                    _logger.LogWarning(
                        "[WorldProxy][DB-GATE] Retail AUTH_SESSION accountId missing. Using fallback account id. AccountId={AccountId}, Source={Source}",
                        accountId,
                        accountIdSource);
                }
                else
                {
                    bridgeState.SetEvidenceContext("DB", "db parity gate");
                    bridgeState.MarkTemporalInvariant(
                        name: "db_parity_gate",
                        passed: false,
                        expected: "Retail AUTH_SESSION carries a non-zero accountId or fallback resolution finds one.",
                        actual: "Retail AUTH_SESSION accountId is missing and no fallback account id is available.");
                    _logger.LogWarning(
                        "[WorldProxy][DB-GATE] Rejected before protocol rewrite: Retail auth session has no valid accountId and fallback resolution failed.");
                    return null;
                }
            }

            AcoreSessionMaterial? material = await _worldSessionMaterialRepository.TryReadSessionMaterialByAccountIdAsync(accountId, dbToken).ConfigureAwait(false);
            if (material is null && accountIdSource == "config:AuthAccountIdFallback")
            {
                int? latestAccountId = await _worldSessionMaterialRepository.TryReadLatestSessionMaterialAccountIdAsync(dbToken).ConfigureAwait(false);
                if (latestAccountId is > 0 && latestAccountId.Value != accountId)
                {
                    AcoreSessionMaterial? latestMaterial = await _worldSessionMaterialRepository.TryReadSessionMaterialByAccountIdAsync(latestAccountId.Value, dbToken).ConfigureAwait(false);
                    if (latestMaterial is not null)
                    {
                        accountId = latestAccountId.Value;
                        accountIdSource = "db:adapter_world_session_material.latest";
                        material = latestMaterial;
                        _logger.LogWarning(
                            "[WorldProxy][DB-GATE] AuthAccountIdFallback had no session material; switched to latest adapter world session material. AccountId={AccountId}",
                            accountId);
                    }
                }
            }

            if (material is null)
            {
                bridgeState.SetEvidenceContext("DB", "db parity gate");
                bridgeState.MarkTemporalInvariant(
                    name: "db_parity_gate",
                    passed: false,
                    expected: "Account/session material exists in auth DB for resolved account id.",
                    actual: $"No DB row/material for account id {accountId} (source={accountIdSource}).");
                _logger.LogWarning(
                    "[WorldProxy][BRIDGE] Strict session key lookup failed for AccountId={AccountId}, Source={Source}.",
                    accountId,
                    accountIdSource);
                return null;
            }

            AcoreSessionMaterial account = material.Value;
            RetailAuthSessionFrame effectiveRetailFrame = retailFrame with { AccountId = accountId };
            DbParityGateResult dbGateResult = DbParityGateEvaluator.Evaluate(
                effectiveRetailFrame,
                account,
                WorldGatewayProtocolConstants.AcoreSessionKeyBytes,
                _options.AcoreRealmId,
                _options.AcoreClientBuild);
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: dbGateResult.Passed,
                expected: dbGateResult.Expected,
                actual: dbGateResult.Actual);
            if (!dbGateResult.Passed)
            {
                bridgeState.SetEvidenceContext("DB", "db parity gate");
                _logger.LogWarning(
                    "[WorldProxy][DB-GATE] Rejected before protocol rewrite. AccountId={AccountId}, Reason={Reason}",
                    account.AccountId,
                    dbGateResult.FailureReason);
                return null;
            }

            byte[] digest = AcoreAuthSessionBuilder.BuildAcoreDigest(
                account.AccountName,
                retailFrame.LocalChallenge4,
                authSeed,
                account.SessionKey,
                Sha1ZeroPrefix,
                WorldGatewayProtocolConstants.AcoreAuthDigestBytes);

            byte[] addonInfo = AcoreAuthSessionBuilder.BuildMinimalAddonInfoBlob();
            byte[] payload = AcoreAuthSessionBuilder.BuildAcoreAuthSessionPayload(
                effectiveRetailFrame,
                account.AccountName,
                digest,
                addonInfo,
                _options.AcoreClientBuild,
                _options.AcoreRealmId);
            byte[] frame = AcoreFrameBuilder.BuildAcoreClientFrame(WorldGatewayOpcodes.AcoreCmsgAuthSession, payload);
            var authCrypt = new AuthCrypt();
            authCrypt.Init(account.SessionKey);

            CryptographicOperations.ZeroMemory(digest);
            return new AcoreAuthSessionBridgeResult(frame, authCrypt, account.SessionKey, account.BnetKeyData64, accountId, accountIdSource);
        }
        catch (OperationCanceledException) when (dbCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            bridgeState.SetEvidenceContext("DB", "db auth bridge timeout gate");
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: false,
                expected: "DB/auth bridge queries complete within configured timeout budget.",
                actual: $"auth bridge DB timeout after {_options.AuthBridgeDbTimeoutMs}ms.");
            bridgeState.MarkTemporalInvariant(
                name: "db_auth_bridge_timeout_gate",
                passed: false,
                expected: "DB/auth bridge should not exceed timeout budget.",
                actual: $"timeout_ms={_options.AuthBridgeDbTimeoutMs}");
            _logger.LogWarning(
                "[WorldProxy][DB-GATE] Auth bridge DB timeout. TimeoutMs={TimeoutMs}. Rejecting AUTH_SESSION bridge for this connection.",
                _options.AuthBridgeDbTimeoutMs);
            return null;
        }
        catch (Exception ex) when (ex is MySqlException or IOException or CryptographicException or InvalidOperationException)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][BRIDGE] Exception while building AC auth session frame.");
            bridgeState.SetEvidenceContext("DB", "db parity gate");
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: false,
                expected: "DB parity gate should pass without runtime exceptions.",
                actual: ex.GetType().Name);
            return null;
        }
    }
}
