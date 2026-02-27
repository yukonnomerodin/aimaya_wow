namespace Adapter.WorldGateway;

internal static class AuthResponsePermutationHelpers
{
    public static int[] BuildAccountDataPermutationOrder(int fieldCount, int variantIndex)
    {
        int[] identity = new int[fieldCount];
        for (int idx = 0; idx < fieldCount; idx++)
        {
            identity[idx] = idx;
        }

        if (fieldCount <= 1 || variantIndex < 0)
        {
            return identity;
        }

        int totalPermutations = BuildFactorialNumber(fieldCount);
        int normalizedVariant = variantIndex % totalPermutations;
        if (normalizedVariant == 0)
        {
            return identity;
        }

        var pool = new List<int>(identity);
        var order = new int[fieldCount];
        int remainingVariant = normalizedVariant;
        for (int position = 0; position < fieldCount; position++)
        {
            int remaining = fieldCount - position;
            int bucketSize = BuildFactorialNumber(remaining - 1);
            int selectedIndex = remainingVariant / bucketSize;
            remainingVariant %= bucketSize;
            order[position] = pool[selectedIndex];
            pool.RemoveAt(selectedIndex);
        }

        return order;
    }

    private static int BuildFactorialNumber(int value)
    {
        int result = 1;
        for (int current = 2; current <= value; current++)
        {
            result *= current;
        }

        return result;
    }
}
