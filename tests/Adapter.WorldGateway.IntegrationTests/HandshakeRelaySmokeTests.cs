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
}
