using System.Text;

namespace Adapter.WorldGateway;

internal static class MatrixPolicyGuard
{
    public static bool TryFindRejectedChangeSet(string matrixPath, string singleChangedVariable, out string? rejectedHypothesisId)
    {
        rejectedHypothesisId = null;

        if (string.IsNullOrWhiteSpace(singleChangedVariable) || !File.Exists(matrixPath))
        {
            return false;
        }

        try
        {
            foreach (string line in File.ReadLines(matrixPath, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                if (line.StartsWith("hypothesis_id,", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!TryParseCsvColumns(line, out string[] columns) || columns.Length < 8)
                {
                    continue;
                }

                string columnSingleChangedVariable = columns[3].Trim();
                string decision = columns[7].Trim();
                if (!string.Equals(decision, "rejected", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (IsBenignRejectedRow(columns))
                {
                    continue;
                }

                if (!string.Equals(columnSingleChangedVariable, singleChangedVariable, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                rejectedHypothesisId = columns[0].Trim();
                return true;
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

        return false;
    }

    private static bool IsBenignRejectedRow(string[] columns)
    {
        if (columns.Length < 8)
        {
            return false;
        }

        // Synthetic probe runs can end with disconnect reason=14 after reaching CHAR_ENUM_RECEIVED.
        // Those runs are operationally valid and must not hard-block a replay of the same refactor variable.
        string failureClass = columns[6].Trim();
        if (!string.Equals(failureClass, "reason=14", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string actualObservable = columns[5];
        bool runValidTrue = actualObservable.IndexOf("run_valid=True", StringComparison.OrdinalIgnoreCase) >= 0;
        bool reachedCharEnum = actualObservable.IndexOf("stage=CHAR_ENUM_RECEIVED", StringComparison.OrdinalIgnoreCase) >= 0;
        return runValidTrue && reachedCharEnum;
    }

    private static bool TryParseCsvColumns(string line, out string[] columns)
    {
        var values = new List<string>(12);
        var sb = new StringBuilder(line.Length);
        bool inQuotes = false;

        for (int idx = 0; idx < line.Length; idx++)
        {
            char ch = line[idx];
            if (ch == '"')
            {
                if (inQuotes && idx + 1 < line.Length && line[idx + 1] == '"')
                {
                    sb.Append('"');
                    idx++;
                    continue;
                }

                inQuotes = !inQuotes;
                continue;
            }

            if (ch == ',' && !inQuotes)
            {
                values.Add(sb.ToString());
                sb.Clear();
                continue;
            }

            sb.Append(ch);
        }

        if (inQuotes)
        {
            columns = Array.Empty<string>();
            return false;
        }

        values.Add(sb.ToString());
        columns = values.ToArray();
        return true;
    }
}
