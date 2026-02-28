using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Adapter.WorldGateway;

internal static class WorldProxyConfigParsers
{
    public static RelayFailureRecoveryPolicy ParseRelayFailureRecoveryPolicy(string? value, out bool valid)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            valid = true;
            return RelayFailureRecoveryPolicy.CancelSiblingAndClose;
        }

        string normalized = value.Trim().ToLowerInvariant();
        valid = true;
        return normalized switch
        {
            "cancel_sibling_and_close" => RelayFailureRecoveryPolicy.CancelSiblingAndClose,
            "cancel-sibling-and-close" => RelayFailureRecoveryPolicy.CancelSiblingAndClose,
            "cancelandclose" => RelayFailureRecoveryPolicy.CancelSiblingAndClose,
            "cancel_sibling_drain_and_close" => RelayFailureRecoveryPolicy.CancelSiblingDrainAndClose,
            "cancel-sibling-drain-and-close" => RelayFailureRecoveryPolicy.CancelSiblingDrainAndClose,
            "drain" => RelayFailureRecoveryPolicy.CancelSiblingDrainAndClose,
            _ => ParseRelayFailureRecoveryPolicyInvalid(out valid)
        };
    }

    public static HandshakeDiagnosticsDispatchMode ParseHandshakeDiagnosticsDispatchMode(string? value, out bool valid)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            valid = true;
            return HandshakeDiagnosticsDispatchMode.Sync;
        }

        string normalized = value.Trim().ToLowerInvariant();
        valid = true;
        return normalized switch
        {
            "sync" => HandshakeDiagnosticsDispatchMode.Sync,
            "background_channel" => HandshakeDiagnosticsDispatchMode.BackgroundChannel,
            "background-channel" => HandshakeDiagnosticsDispatchMode.BackgroundChannel,
            "background" => HandshakeDiagnosticsDispatchMode.BackgroundChannel,
            _ => ParseHandshakeDiagnosticsDispatchModeInvalid(out valid)
        };
    }

    public static BootstrapFlushTriggerMode ParseBootstrapFlushTriggerMode(string? value, out bool valid)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            valid = true;
            return BootstrapFlushTriggerMode.Ack;
        }

        string normalized = value.Trim().ToLowerInvariant();
        valid = true;
        return normalized switch
        {
            "ack" => BootstrapFlushTriggerMode.Ack,
            "first_client_post_ack_non_ack" => BootstrapFlushTriggerMode.FirstClientPostAckNonAck,
            "first-client-post-ack-non-ack" => BootstrapFlushTriggerMode.FirstClientPostAckNonAck,
            "firstclientpostacknonack" => BootstrapFlushTriggerMode.FirstClientPostAckNonAck,
            _ => ParseBootstrapFlushTriggerModeInvalid(out valid)
        };
    }

    public static bool TryResolveAckGateFromDecisionArtifact(
        string? decisionPath,
        out bool gate,
        out string resolvedPath)
    {
        gate = false;
        resolvedPath = string.Empty;

        if (string.IsNullOrWhiteSpace(decisionPath))
        {
            return false;
        }

        resolvedPath = Path.IsPathRooted(decisionPath)
            ? decisionPath
            : Path.Combine(WorldGatewayPathResolver.ResolveProjectRoot(), decisionPath);
        if (!File.Exists(resolvedPath))
        {
            return false;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(resolvedPath, Encoding.UTF8));
            JsonElement root = doc.RootElement;

            if (root.TryGetProperty("effective_ack_gate", out JsonElement effectiveAckElement) &&
                (effectiveAckElement.ValueKind == JsonValueKind.True || effectiveAckElement.ValueKind == JsonValueKind.False))
            {
                gate = effectiveAckElement.GetBoolean();
                return true;
            }

            if (root.TryGetProperty("recommended_ack_policy", out JsonElement recommendedPolicyElement) &&
                recommendedPolicyElement.ValueKind == JsonValueKind.String)
            {
                AckPolicyMode mode = AckPolicyResolver.Parse(recommendedPolicyElement.GetString());
                if (mode == AckPolicyMode.Gate)
                {
                    gate = true;
                    return true;
                }

                if (mode == AckPolicyMode.NonBlocking)
                {
                    gate = false;
                    return true;
                }
            }

            if (root.TryGetProperty("winner", out JsonElement winnerElement) &&
                winnerElement.ValueKind == JsonValueKind.String)
            {
                AckPolicyMode winnerMode = AckPolicyResolver.Parse(winnerElement.GetString());
                if (winnerMode == AckPolicyMode.Gate)
                {
                    gate = true;
                    return true;
                }

                if (winnerMode == AckPolicyMode.NonBlocking)
                {
                    gate = false;
                    return true;
                }
            }
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    public static bool TryParseFlexibleUInt32(string? value, out uint parsed)
    {
        parsed = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string input = value.Trim();
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(input.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed);
        }

        return uint.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
    }

    public static bool TryParseProbeDropDeferredOpcodes(string rawValue, HashSet<uint> destination, out string? error)
    {
        error = null;
        destination.Clear();

        string[] tokens = rawValue.Split(
            [',', ';', '|', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (tokens.Length == 0)
        {
            error = "empty opcode list";
            return false;
        }

        foreach (string token in tokens)
        {
            if (!TryParseFlexibleUInt32(token, out uint opcode))
            {
                error = $"invalid opcode token '{token}'";
                destination.Clear();
                return false;
            }

            destination.Add(opcode);
        }

        if (destination.Count == 0)
        {
            error = "no valid opcode tokens";
            return false;
        }

        return true;
    }

    public static IPAddress ParseBindAddress(string address)
    {
        if (string.IsNullOrWhiteSpace(address) ||
            address == "*" ||
            address == "0.0.0.0")
        {
            return IPAddress.Any;
        }

        if (address == "::" || address == "[::]")
        {
            return IPAddress.IPv6Any;
        }

        return IPAddress.Parse(address);
    }

    private static BootstrapFlushTriggerMode ParseBootstrapFlushTriggerModeInvalid(out bool valid)
    {
        valid = false;
        return BootstrapFlushTriggerMode.Ack;
    }

    private static RelayFailureRecoveryPolicy ParseRelayFailureRecoveryPolicyInvalid(out bool valid)
    {
        valid = false;
        return RelayFailureRecoveryPolicy.CancelSiblingAndClose;
    }

    private static HandshakeDiagnosticsDispatchMode ParseHandshakeDiagnosticsDispatchModeInvalid(out bool valid)
    {
        valid = false;
        return HandshakeDiagnosticsDispatchMode.Sync;
    }
}
