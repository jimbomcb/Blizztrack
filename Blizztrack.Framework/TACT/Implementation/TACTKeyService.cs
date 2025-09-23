using System.Collections.Concurrent;

namespace Blizztrack.Framework.TACT.Implementation;

/// <summary>
/// Static collection of TACT keys referenced by the BLTE parser when encountering encrypted chunks.
/// </summary>
public class TACTKeyService
{
    private static readonly ConcurrentDictionary<ulong, byte[]> _keys = new();
    private static readonly Lazy<Salsa20> _salsaInstance = new(() => new Salsa20());

    public static Salsa20 SalsaInstance => _salsaInstance.Value;

    public static bool TryGetKey(ulong keyName, out byte[] key)
    {
        return _keys.TryGetValue(keyName, out key!);
    }

    public static void SetKey(ulong keyName, byte[] key)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));

        _keys[keyName] = key;
    }

    public static void ClearKeys()
    {
        _keys.Clear();
    }

    public static int KeyCount => _keys.Count;
}