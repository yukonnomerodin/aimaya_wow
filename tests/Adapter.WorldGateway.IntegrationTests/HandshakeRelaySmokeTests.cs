using System.Text.Json;

namespace Adapter.WorldGateway.IntegrationTests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class GatewaySmokeCollection
{
    public const string Name = "GatewaySmoke";
}

[Collection(GatewaySmokeCollection.Name)]
public sealed class HandshakeRelaySmokeTests : IClassFixture<GatewaySmokeFixture>
{
    private readonly GatewaySmokeFixture _fixture;

    public HandshakeRelaySmokeTests(GatewaySmokeFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void HandshakeRun_IsValidAndAtBoundaryNineOfNine()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (!_fixture.IsEnabled)
        {
            return;
        }

        JsonElement root = AssertJson(_fixture.ValidationJson);
        Assert.True(GetRequiredBoolean(root, "run_valid"));
        Assert.True(GetRequiredBoolean(root, "ack_observed"));
        Assert.Equal("9/9", GetRequiredString(root, "boundary"));
        Assert.NotEqual("<none>", GetRequiredString(root, "report_path"));
    }

    [Fact]
    public void RelayRun_EmitsPostAckEvidenceAndDeferredFrameMarker()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (!_fixture.IsEnabled)
        {
            return;
        }

        JsonElement probeRoot = AssertJson(_fixture.ProbeJson);
        Assert.True(GetRequiredBoolean(probeRoot, "enter_encrypted_seen"));
        Assert.True(GetRequiredBoolean(probeRoot, "ack_sent"));

        JsonElement postAckOpcodes = GetRequiredProperty(probeRoot, "post_ack_observed_opcodes");
        Assert.Equal(JsonValueKind.Array, postAckOpcodes.ValueKind);
        Assert.True(postAckOpcodes.GetArrayLength() > 0);

        JsonElement validationRoot = AssertJson(_fixture.ValidationJson);
        Assert.NotEqual("<none>", GetRequiredString(validationRoot, "deferred_first"));
        Assert.NotEqual("<none>", GetRequiredString(validationRoot, "deferred_flush_path"));
    }

    [Fact]
    public void BoundaryContract_ContainsAckDeferredAndDbInvariants()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (!_fixture.IsEnabled)
        {
            return;
        }

        JsonElement reportRoot = AssertJson(_fixture.ReportJson);
        Assert.True(GetRequiredBoolean(reportRoot, "ack_observed"));
        Assert.NotEqual("<none>", GetRequiredString(reportRoot, "deferred_flush_path"));

        JsonElement temporalInvariants = GetRequiredProperty(reportRoot, "temporal_invariants");
        Assert.Equal(JsonValueKind.Array, temporalInvariants.ValueKind);
        Assert.True(ContainsInvariant(temporalInvariants, "enter_encrypted_ack_within_timeout"));
        Assert.True(ContainsInvariant(temporalInvariants, "db_parity_gate"));
    }

    [Fact]
    public void BoundaryContract_ContainsServiceBoundaryAndRecoveryMetadata()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (!_fixture.IsEnabled)
        {
            return;
        }

        JsonElement reportRoot = AssertJson(_fixture.ReportJson);
        Assert.Equal("r6.service_boundary.v1", GetRequiredString(reportRoot, "service_boundary_contract_version"));
        Assert.True(GetRequiredInt(reportRoot, "db_auth_bridge_timeout_ms") > 0);
        Assert.True(GetRequiredInt(reportRoot, "relay_failure_drain_timeout_ms") >= 0);
        Assert.NotEqual(string.Empty, GetRequiredString(reportRoot, "relay_failure_recovery_policy"));
        Assert.NotEqual(string.Empty, GetRequiredString(reportRoot, "handshake_diagnostics_dispatch_mode"));
        Assert.True(GetRequiredLong(reportRoot, "handshake_diagnostics_queue_enqueue_attempt_total") >= 0);
        Assert.True(GetRequiredLong(reportRoot, "handshake_diagnostics_queue_enqueued_total") >= 0);
        Assert.True(GetRequiredLong(reportRoot, "handshake_diagnostics_queue_saturation_fallback_total") >= 0);
    }

    private static JsonElement AssertJson(JsonDocument? json)
    {
        Assert.NotNull(json);
        return json!.RootElement;
    }

    private static JsonElement GetRequiredProperty(JsonElement root, string propertyName)
    {
        Assert.True(root.TryGetProperty(propertyName, out JsonElement value), $"Missing property '{propertyName}' in JSON payload.");
        return value;
    }

    private static bool GetRequiredBoolean(JsonElement root, string propertyName)
    {
        return GetRequiredProperty(root, propertyName).GetBoolean();
    }

    private static string GetRequiredString(JsonElement root, string propertyName)
    {
        return GetRequiredProperty(root, propertyName).GetString() ?? string.Empty;
    }

    private static int GetRequiredInt(JsonElement root, string propertyName)
    {
        return GetRequiredProperty(root, propertyName).GetInt32();
    }

    private static long GetRequiredLong(JsonElement root, string propertyName)
    {
        return GetRequiredProperty(root, propertyName).GetInt64();
    }

    private static bool ContainsInvariant(JsonElement temporalInvariants, string invariantName)
    {
        foreach (JsonElement item in temporalInvariants.EnumerateArray())
        {
            if (!item.TryGetProperty("Name", out JsonElement nameElement))
            {
                continue;
            }

            if (string.Equals(nameElement.GetString(), invariantName, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
