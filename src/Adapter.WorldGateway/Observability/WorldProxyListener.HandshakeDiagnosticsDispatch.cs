using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct HandshakeLabReportWriteRequest(
        uint ConnectionId,
        HandshakeLabReport Report,
        string RunlogsDirectory,
        string ProofPackRoot);

    private void StartHandshakeDiagnosticsDispatcher()
    {
        if (_handshakeDiagnosticsDispatchMode != HandshakeDiagnosticsDispatchMode.BackgroundChannel ||
            _handshakeDiagnosticsChannel is null ||
            _handshakeDiagnosticsDrainTask is not null)
        {
            return;
        }

        _handshakeDiagnosticsDrainTask = Task.Run(ProcessHandshakeDiagnosticsQueueAsync);
    }

    private async ValueTask StopHandshakeDiagnosticsDispatcherAsync()
    {
        if (_handshakeDiagnosticsChannel is null || _handshakeDiagnosticsDrainTask is null)
        {
            return;
        }

        _handshakeDiagnosticsChannel.Writer.TryComplete();
        try
        {
            await _handshakeDiagnosticsDrainTask.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[WorldProxy][HANDSHAKE-LAB] Diagnostics dispatcher finished with error.");
        }
        finally
        {
            _handshakeDiagnosticsDrainTask = null;
        }
    }

    private bool TryEnqueueHandshakeLabReport(HandshakeLabReportWriteRequest request)
    {
        if (_handshakeDiagnosticsChannel is null)
        {
            return false;
        }

        if (_handshakeDiagnosticsChannel.Writer.TryWrite(request))
        {
            return true;
        }

        _logger.LogWarning(
            "[WorldProxy][HANDSHAKE-LAB] Diagnostics queue is saturated. Falling back to synchronous write. ConnectionId={ConnectionId}, QueueCapacity={QueueCapacity}",
            request.ConnectionId,
            _options.HandshakeDiagnosticsBackgroundQueueCapacity);
        return false;
    }

    private async Task ProcessHandshakeDiagnosticsQueueAsync()
    {
        if (_handshakeDiagnosticsChannel is null)
        {
            return;
        }

        await foreach (HandshakeLabReportWriteRequest request in _handshakeDiagnosticsChannel.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            WriteHandshakeLabReportCore(request);
        }
    }

    private void WriteHandshakeLabReportCore(in HandshakeLabReportWriteRequest request)
    {
        string reportPath = HandshakeDiagnosticsWriters.WriteHandshakeLabReport(
            request.Report,
            request.RunlogsDirectory);
        HandshakeDiagnosticsWriters.AppendNegativeEvidenceMatrixRow(
            reportPath,
            request.Report,
            request.ProofPackRoot);
        _logger.LogInformation(
            "[WorldProxy][HANDSHAKE-LAB] Report written. ConnectionId={ConnectionId}, Path={Path}, DispatchMode={DispatchMode}",
            request.ConnectionId,
            reportPath,
            _handshakeDiagnosticsDispatchMode);
    }
}
