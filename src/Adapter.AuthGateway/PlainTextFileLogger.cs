using Microsoft.Extensions.Logging;
using System;
using System.Globalization;
using System.IO;

namespace Adapter.AuthGateway;

internal sealed class PlainTextFileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly object _sync = new();
    private bool _disposed;

    public PlainTextFileLoggerProvider(string path)
    {
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        _writer = new StreamWriter(stream)
        {
            AutoFlush = true
        };
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new PlainTextFileLogger(categoryName, _writer, _sync);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        lock (_sync)
        {
            _writer.Dispose();
        }

        _disposed = true;
    }

    private sealed class PlainTextFileLogger : ILogger
    {
        private readonly string _categoryName;
        private readonly StreamWriter _writer;
        private readonly object _sync;

        public PlainTextFileLogger(string categoryName, StreamWriter writer, object sync)
        {
            _categoryName = categoryName;
            _writer = writer;
            _sync = sync;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel != LogLevel.None;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            string message = formatter(state, exception);
            if (string.IsNullOrEmpty(message) && exception is null)
            {
                return;
            }

            string timestamp = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture);
            string level = logLevel.ToString().ToLowerInvariant();

            lock (_sync)
            {
                _writer.Write(timestamp);
                _writer.Write(' ');
                _writer.Write(level);
                _writer.Write(": ");
                _writer.Write(_categoryName);
                _writer.Write('[');
                _writer.Write(eventId.Id);
                _writer.Write("] ");
                _writer.WriteLine(message);

                if (exception is not null)
                {
                    _writer.WriteLine(exception);
                }
            }
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static NullScope Instance { get; } = new();

        private NullScope()
        {
        }

        public void Dispose()
        {
        }
    }
}
