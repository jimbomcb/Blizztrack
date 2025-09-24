using System.IO.Compression;
using System.Runtime.CompilerServices;

namespace Blizztrack.Framework
{
    /// <summary>
    /// Slower version of the Zlib handler that uses the managed implementation, 
    /// mainly because I don't want to fuck with library paths in the containers 
    /// Specifically libSystem.IO.Compression.Native.so isn't on the LD_LIBRARY_PATH
    /// </summary>
    public partial class CompressionSlow
    {
        public static readonly CompressionSlow Instance = new();

        public bool Compress(ReadOnlySpan<byte> input, Span<byte> output, CompressionLevel compressionLevel, int windowBits = 15)
        {
            // Only support zlib format (windowBits = 15)
            if (windowBits != 15)
                throw new ArgumentException("Only zlib format (windowBits = 15) is supported", nameof(windowBits));

            try
            {
                using var outputStream = new MemoryStream(output.Length);
                using var zlibStream = new ZLibStream(outputStream, compressionLevel, leaveOpen: true);

                zlibStream.Write(input);
                zlibStream.Flush();

                var compressedLength = (int)outputStream.Position;
                if (compressedLength > output.Length)
                    return false;

                var compressedData = outputStream.GetBuffer();
                compressedData.AsSpan(0, compressedLength).CopyTo(output);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Decompress(ReadOnlySpan<byte> input, Span<byte> output, int discardOutput = 0, int windowBits = 15)
        {
            // Only support zlib format (windowBits = 15)
            if (windowBits != 15)
                throw new ArgumentException("Only zlib format (windowBits = 15) is supported", nameof(windowBits));

            try
            {
                using var inputStream = new MemoryStream(input.ToArray());
                using var zlibStream = new ZLibStream(inputStream, CompressionMode.Decompress);

                if (discardOutput > 0)
                {
                    var discardBuffer = new byte[Math.Min(8192, discardOutput)];
                    var totalDiscarded = 0;
                    while (totalDiscarded < discardOutput)
                    {
                        var toDiscard = Math.Min(discardBuffer.Length, discardOutput - totalDiscarded);
                        var discarded = zlibStream.Read(discardBuffer, 0, toDiscard);
                        if (discarded == 0)
                            break;
                        totalDiscarded += discarded;
                    }
                }

                var totalRead = 0;
                while (totalRead < output.Length)
                {
                    // read stream straight into span
                    var bytesRead = zlibStream.Read(output.Slice(totalRead));
                    if (bytesRead == 0)
                        break;
                    totalRead += bytesRead;
                }

                return totalRead > 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
