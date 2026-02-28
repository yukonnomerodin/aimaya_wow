using System.Collections.Generic;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ParsedOptionInitializationResult(
        AckPolicyMode AckPolicyMode,
        BootstrapFlushTriggerMode BootstrapFlushTriggerMode,
        bool BootstrapFlushTriggerModeValid,
        uint EnterEncryptedModeOpcode,
        bool EnterEncryptedModeOpcodeValid,
        uint ProbeAuthResponseOpcode,
        bool ProbeAuthResponseOpcodeOverrideProvided,
        bool ProbeAuthResponseOpcodeOverrideValid,
        AuthResponseFuzzMutation AuthResponseFuzzMutation,
        bool AuthResponseFuzzPlanRecognized,
        bool ProbeDropDeferredOpcodeConfigProvided,
        string? ProbeDropDeferredOpcodeParseError,
        IReadOnlyCollection<uint> ProbeDropDeferredOpcodes);

    private static ParsedOptionInitializationResult ParseOptionInitialization(
        WorldProxyOptions options,
        ProtocolEngineeringOptions protocolOptions)
    {
        AckPolicyMode ackPolicyMode = AckPolicyResolver.Parse(protocolOptions.AckPolicy);
        BootstrapFlushTriggerMode bootstrapFlushTriggerMode = WorldProxyConfigParsers.ParseBootstrapFlushTriggerMode(
            options.BootstrapFlushTriggerSource,
            out bool bootstrapFlushTriggerModeValid);

        bool enterEncryptedModeOpcodeValid = WorldProxyConfigParsers.TryParseFlexibleUInt32(
            options.EnterEncryptedModeOpcode,
            out uint enterEncryptedModeOpcode);
        uint probeAuthResponseOpcode = WorldGatewayOpcodes.RetailSmsgAuthResponse;
        if (!enterEncryptedModeOpcodeValid)
        {
            enterEncryptedModeOpcode = WorldGatewayOpcodes.RetailSmsgEnterEncryptedModeDefault;
        }

        bool probeAuthResponseOpcodeOverrideProvided = false;
        bool probeAuthResponseOpcodeOverrideValid = false;
        if (!string.IsNullOrWhiteSpace(options.ProbeAuthResponseOpcodeOverride))
        {
            probeAuthResponseOpcodeOverrideProvided = true;
            probeAuthResponseOpcodeOverrideValid = WorldProxyConfigParsers.TryParseFlexibleUInt32(
                options.ProbeAuthResponseOpcodeOverride,
                out uint parsedAuthOpcode);
            if (probeAuthResponseOpcodeOverrideValid)
            {
                probeAuthResponseOpcode = parsedAuthOpcode;
            }
        }

        AuthResponseFuzzMutation authResponseFuzzMutation = AuthResponseFuzzMutationResolver.Resolve(
            options.ProbeAuthResponseFuzzerEnabled,
            options.ProbeAuthResponseFuzzerPlan,
            options.ProbeAuthResponseFuzzerIteration,
            WorldGatewayOpcodes.RetailSmsgAuthResponseSweepStart,
            WorldGatewayOpcodes.RetailSmsgAuthResponseSweepCount,
            out bool authResponseFuzzPlanRecognized);
        if (authResponseFuzzMutation.Enabled && authResponseFuzzMutation.OpcodeOverride is uint fuzzOpcode)
        {
            probeAuthResponseOpcode = fuzzOpcode;
        }

        bool probeDropDeferredOpcodeConfigProvided = false;
        string? probeDropDeferredOpcodeParseError = null;
        HashSet<uint> probeDropDeferredOpcodes = new();
        if (!string.IsNullOrWhiteSpace(options.ProbeDropDeferredOpcode))
        {
            probeDropDeferredOpcodeConfigProvided = true;
            if (!WorldProxyConfigParsers.TryParseProbeDropDeferredOpcodes(
                    options.ProbeDropDeferredOpcode,
                    probeDropDeferredOpcodes,
                    out string? parseError))
            {
                probeDropDeferredOpcodeParseError = parseError;
            }
        }

        return new ParsedOptionInitializationResult(
            AckPolicyMode: ackPolicyMode,
            BootstrapFlushTriggerMode: bootstrapFlushTriggerMode,
            BootstrapFlushTriggerModeValid: bootstrapFlushTriggerModeValid,
            EnterEncryptedModeOpcode: enterEncryptedModeOpcode,
            EnterEncryptedModeOpcodeValid: enterEncryptedModeOpcodeValid,
            ProbeAuthResponseOpcode: probeAuthResponseOpcode,
            ProbeAuthResponseOpcodeOverrideProvided: probeAuthResponseOpcodeOverrideProvided,
            ProbeAuthResponseOpcodeOverrideValid: probeAuthResponseOpcodeOverrideValid,
            AuthResponseFuzzMutation: authResponseFuzzMutation,
            AuthResponseFuzzPlanRecognized: authResponseFuzzPlanRecognized,
            ProbeDropDeferredOpcodeConfigProvided: probeDropDeferredOpcodeConfigProvided,
            ProbeDropDeferredOpcodeParseError: probeDropDeferredOpcodeParseError,
            ProbeDropDeferredOpcodes: probeDropDeferredOpcodes);
    }
}
