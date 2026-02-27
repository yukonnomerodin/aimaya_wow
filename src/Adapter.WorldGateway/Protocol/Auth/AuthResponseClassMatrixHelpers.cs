namespace Adapter.WorldGateway;

internal static class AuthResponseClassMatrixHelpers
{
    // Prefix of TrinityCore class_expansion_requirement rows used for payload-size parity probing.
    // Source: sql/old/9.x/world/21081_2021_10_15/2021_09_11_00_world.sql
    private static readonly (byte RaceId, byte ClassId)[] TrinityLegacyClassMatrixRows =
    [
        (1, 1), (1, 2), (1, 4), (1, 5), (1, 8), (1, 9), (1, 6), (1, 3), (1, 10),
        (2, 1), (2, 3), (2, 4), (2, 7), (2, 9), (2, 6), (2, 8), (2, 10),
        (3, 1), (3, 2), (3, 3), (3, 5), (3, 4), (3, 6), (3, 8), (3, 7), (3, 9), (3, 10),
        (4, 1), (4, 3), (4, 4), (4, 5), (4, 11), (4, 6), (4, 8), (4, 10), (4, 12),
        (5, 1), (5, 4), (5, 5), (5, 8), (5, 9), (5, 6), (5, 3), (5, 10),
        (6, 1), (6, 3), (6, 7), (6, 11), (6, 6), (6, 5), (6, 2), (6, 10),
        (7, 1), (7, 4), (7, 8), (7, 9)
    ];

    public static int LegacyRowCount => TrinityLegacyClassMatrixRows.Length;

    public static (byte ActiveExpansionLevel, byte AccountExpansionLevel, byte MinActiveExpansionLevel) GetLegacyClassExpansionRequirement(byte classId)
    {
        return classId switch
        {
            6 => (2, 0, 2),  // Death Knight
            10 => (4, 0, 4), // Monk
            _ => (0, 0, 0)
        };
    }

    public static List<(byte RaceId, byte[] ClassIds)> BuildLegacyClassMatrixPrefix(int rowCount)
    {
        int normalizedRows = Math.Clamp(rowCount, 1, TrinityLegacyClassMatrixRows.Length);
        var raceOrder = new List<byte>(16);
        var raceClasses = new Dictionary<byte, List<byte>>();

        for (int index = 0; index < normalizedRows; index++)
        {
            (byte raceId, byte classId) = TrinityLegacyClassMatrixRows[index];
            if (!raceClasses.TryGetValue(raceId, out List<byte>? classList))
            {
                classList = new List<byte>(16);
                raceClasses[raceId] = classList;
                raceOrder.Add(raceId);
            }

            if (!classList.Contains(classId))
            {
                classList.Add(classId);
            }
        }

        var matrix = new List<(byte RaceId, byte[] ClassIds)>(raceOrder.Count);
        foreach (byte raceId in raceOrder)
        {
            matrix.Add((raceId, raceClasses[raceId].ToArray()));
        }

        return matrix;
    }
}
