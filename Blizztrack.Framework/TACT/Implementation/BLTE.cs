using Blizztrack.Framework.Extensions;
using Blizztrack.Framework.TACT.Resources;
using Blizztrack.Shared.Extensions;
using Blizztrack.Shared.IO;

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using static Blizztrack.Framework.TACT.Implementation.Install;

namespace Blizztrack.Framework.TACT.Implementation
{
    /// <summary>
    /// This object describes a specific BLTE schema.
    /// 
    /// <para>
    /// There are multiple ways to use this object; it can be used to create a schema
    /// that can later be used to parse a <see cref="ResourceHandle" />,
    /// or can be used to directly extract the compressed bytes.
    /// </para>
    /// </summary>
    /// <remarks>When using the two-steps implementation, it is primordial to make sure
    /// the same <see cref="ResourceHandle" /> is used both at 
    /// <see cref="ParseSchema(ResourceHandle, long)" >schema generation</see> time as
    /// well as <see cref="Execute(ResourceHandle)">extraction time</see>,
    /// as instances of this object are effectively hardcoded to work for a specific
    /// schema. At the very least, make sure the compression schema is identical if
    /// cross-using this object. You can rely on
    /// <see cref="Encoding.FindSpecification{T}(T)"/> for this.</remarks>
    /// <example>
    /// <code>
    /// // Example of use of the two-steps implementation.
    /// ResourceHandle handle = ...;
    /// var schema = BLTE.ParseSchema(handle);
    /// var decompressedBytes = schema.Execute(handle);
    /// 
    /// // Example of incorrect use of the two-steps implementation.
    /// ResourceHandle schemaHandle = ...;
    /// ResourceHandle extractionHandle = ...;
    /// Debug.Assert(schemaHandle != extractionHandle);
    /// var schema = BLTE.ParseSchema(handle);
    /// // Note that this is called on a different resource handle than the one used to parse.
    /// // This is usually not recommended but will be fine if you can guarantee that both
    /// // resources are using the same schema.
    /// var decompressedBytes = schema.Execute(extractionHandle);
    /// 
    /// // Example of use of the single-step implementation
    /// ResourceHandle handle = ...;
    /// var decompressedBytes = BLTE.Parse(handle);
    /// 
    /// // You are also able to extract part of a file. In that situation, you must use the two-phase extraction logic:
    /// ResourceHandle handle = ...;
    /// var schema = BLTE.ParseSchema(handle);
    /// // The ranges provided below are relative to the decompressed file.
    /// var decompressedFragment = schema.Execute(handle, 0..1024);
    /// var decompressedFragment = schema.Execute(handle, 100..200);
    /// </code>
    /// </example>
    public readonly struct BLTE
    {
        private readonly ChunkInfo[] _chunks;
        private readonly int _decompressedSize;

        public readonly int Flags;

        private BLTE(int flags, int decompressedSize, ChunkInfo[] chunks)
        {
            _chunks = chunks;
            _decompressedSize = decompressedSize;

            Flags = flags;
        }

        #region Stream support
        public static async Task<MemoryStream> Execute(Stream sourceStream, string? specification, int decompressedSize = 0, CancellationToken stoppingToken = default)
        {
            var schema = await ParseSchema(sourceStream, specification, decompressedSize, stoppingToken);
            return await schema.Execute(sourceStream, stoppingToken);
        }

        public static async Task<BLTE> ParseSchema(Stream sourceStream, string? specification, int decompressedSize = 0, CancellationToken stoppingToken = default)
        {
            // 1. Read the top of the file.
            var dataBuffer = new byte[8];
            await sourceStream.ReadExactlyAsync(dataBuffer, stoppingToken);

            if (BinaryPrimitives.ReadUInt32LittleEndian(dataBuffer) != 0x45544C42u)
                throw new InvalidOperationException("The provided stream does not encapsulate a BLTE resource.");

            var headerSize = BinaryPrimitives.ReadInt32BigEndian(dataBuffer.AsSpan(4));

            // 2. Construct a complete header
            var fileHeader = GC.AllocateUninitializedArray<byte>(headerSize);
            Buffer.BlockCopy(dataBuffer, 0, fileHeader, 0, 8);
            await sourceStream.ReadExactlyAsync(fileHeader.AsMemory(8), stoppingToken);

            // 3. Parse the header.
            var dataSource = fileHeader.ToDataSource();
            var (flags, chunks, _encodingKey) = ParseHeader(dataSource, 0, 0);

            Debug.Assert(decompressedSize == 0 || decompressedSize == chunks[^1].Decompressed.End.Value);

            // 4. Read the spec string.
            if (specification is not null)
            {
                var chunkSpec = Spec.Parse(specification);

                // 5. Update chunks with the compression modes.
                var visitor = new SpecVisitor(chunks.AsBackingArray());
                chunkSpec.Accept(ref visitor, chunks[^1].Decompressed.End.Value);
            }

            return new BLTE(flags, chunks[^1].Decompressed.End.Value, [.. chunks]);
        }

        private delegate void DegradedChunkCorrector(ref ChunkInfo _, byte __);

        public async Task<MemoryStream> Execute(Stream sourceStream, CancellationToken stoppingToken = default)
        {
            var outputBuffer = GC.AllocateUninitializedArray<byte>(_decompressedSize);

            DegradedChunkCorrector corrector = isDegraded(ref _chunks[0]) ? updateChunk : noOp;

            for (var i = 0; i < _chunks.Length; ++i)
            {
                var compressedChunkSize = _chunks[i].CompressedSize + 1;
                var decompressedChunkEnd = _chunks[i].Decompressed.End.Value;
                var outputRange = _chunks[i].Decompressed;

                var inputBuffer = getInputBuffer(compressedChunkSize, decompressedChunkEnd, outputBuffer, _decompressedSize);
                await sourceStream.ReadExactlyAsync(inputBuffer, stoppingToken);

                unsafe {
                    var dataSpan = inputBuffer.Span;
                    corrector(ref _chunks[i], dataSpan[0]);

                    if (_chunks[i].IsEncrypted)
                        ParseEncryptedChunk(dataSpan[1..], outputBuffer.AsSpan(outputRange), i);
                    else
                        _chunks[i].Parser(dataSpan[1..], outputBuffer.AsSpan(outputRange), 0);
                }
            }

            return new MemoryStream(outputBuffer);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static unsafe bool isDegraded(ref ChunkInfo chunk) => chunk.Parser is null;
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static unsafe void noOp(ref ChunkInfo _, byte __) { }

            static unsafe void updateChunk(ref ChunkInfo chunk, byte compressionByte)
                => chunk.Parser = compressionByte switch {
                    (byte)'N' => &ParseImmediate,
                    (byte)'Z' => &ParseCompressed,
                    (byte)'E' => throw new InvalidOperationException("Encrypted chunks should already be marked during schema parsing"),
                    _ => throw new NotImplementedException($"Unsupported compression mode: {(char)compressionByte}"),
                };

            static Memory<byte> getInputBuffer(int compressedChunkSize, int decompressedChunkEnd, byte[] outputBuffer, long decompressedSize)
            {
                // If there is enough space right after this chunk's decompressed data for the compressed data,
                // use that space as a scrap buffer to save an allocation
                if (compressedChunkSize + decompressedChunkEnd <= decompressedSize)
                    return new ArraySegment<byte>(outputBuffer, decompressedChunkEnd, compressedChunkSize);

                // Otherwise, allocate a temporary buffer
                return GC.AllocateUninitializedArray<byte>(compressedChunkSize);
            }
        }

        private ref struct SpecVisitor(Span<ChunkInfo> chunks) : Spec.IVisitor
        {
            private readonly Span<ChunkInfo> _chunks = chunks;
            private int _chunkIndex = 0;
            private int _decompressedCursor = 0;

            public void BeginEncryption(string key, string iv)
            {
                ref var currentChunk = ref _chunks[_chunkIndex];
                currentChunk.IsEncrypted = true;
                currentChunk.EncryptionKeyName = Convert.ToUInt64(key, 16);
                currentChunk.EncryptionIV = Convert.FromHexString(iv);
            }
            
            public void EndEncryption()
            {
                // Chunks retain their encryption info
            }

            public unsafe void OnCompressedChunk(int level, int windowBits, int chunkSize)
            {
                // We don't handle compression parameters because the stream provides it to us.
                _chunks[_chunkIndex].Parser = &ParseCompressed;
                UpdateCompressedRange(chunkSize);
            }

            public unsafe void OnRawChunk(int chunkSize)
            {
                _chunks[_chunkIndex].Parser = &ParseImmediate;
                UpdateCompressedRange(chunkSize);
            }

            private void UpdateCompressedRange(int chunkSize)
            {
                ref var currentChunk = ref _chunks[_chunkIndex];
                Debug.Assert(currentChunk.Decompressed.Start.Value == _decompressedCursor
                    && currentChunk.Decompressed.End.Value == _decompressedCursor + chunkSize);

                _decompressedCursor += chunkSize;
                ++_chunkIndex;
            }
        }
        #endregion

        #region Resource handle support
        /// <summary>
        /// Parses the given resource according to its schema and returns an in-memory buffer.
        /// </summary>
        /// <param name="resourceHandle">The resource to parse</param>
        /// <param name="decompressedSize">The expected decompressed size of the file.</param>
        /// <returns>A byte buffer containing the decompressed file.</returns>
        public static byte[] Parse(ResourceHandle resourceHandle, long decompressedSize = 0)
            => ParseSchema(resourceHandle, decompressedSize).Execute(resourceHandle);


        /// <summary>
        /// Attempts to parse a BLTE schema out of the given span. 
        /// </summary>
        /// <typeparam name="K">The type of encoding key.</typeparam>
        /// <param name="resourceHandle">A handle over a resource.</param>
        /// <param name="decompressedSize">The expected decompressed size of the file. If zero, this parameter is ignored</param>
        /// <remarks>
        /// If the checksum calculated does not match <paramref name="encodingKey"/>, <see langword="default" /> is returned.
        /// If the decompressed size does not match <paramref name="decompressedSize"/>, <see langword="default"/> is returned.
        /// </remarks>
        /// <returns>A schema that can then be used to parse a file.</returns>
        public unsafe static BLTE ParseSchema(ResourceHandle resourceHandle, long decompressedSize = 0)
        {
            using var memoryManager = resourceHandle.ToMappedDataSource();

            return ParseSchema(memoryManager[..], decompressedSize);
        }

        /// <summary>
        /// Executes the current schema over the provided resource, returning a new byte buffer containing the decompressed file.
        /// </summary>
        /// <param name="resourceHandle">A handle to a TACT/CASC file system resource.</param>
        /// <returns>A byte buffer containing the decompressed file.</returns>
        public unsafe byte[] Execute(ResourceHandle resourceHandle)
        {
            using var inputData = resourceHandle.ToMappedDataSource();

            var dataBuffer = GC.AllocateUninitializedArray<byte>(_decompressedSize);

            for (var i = 0; i < _chunks.Length; ++i)
            {
                ref var currentChunk = ref _chunks[i];
                var inputSpan = inputData[currentChunk.Compressed];
                var outputSpan = dataBuffer.AsSpan(currentChunk.Decompressed);
                
                if (currentChunk.IsEncrypted)
                {
                    ParseEncryptedChunk(inputSpan, outputSpan, i);
                }
                else if (currentChunk.Parser != null)
                {
                    currentChunk.Parser(inputSpan, outputSpan, 0);
                }
                else
                {
                    // Handle degraded chunks - read compression byte and parse accordingly
                    var compressionByte = inputSpan[0];
                    var actualData = inputSpan[1..];
                    
                    switch ((char)compressionByte)
                    {
                        case 'N':
                            ParseImmediate(actualData, outputSpan, 0);
                            break;
                        case 'Z':
                            ParseCompressed(actualData, outputSpan, 0);
                            break;
                        case 'E':
                            ParseEncryptedChunk(inputSpan, outputSpan, i);
                            break;
                        default:
                            throw new NotImplementedException($"Unsupported compression mode: {(char)compressionByte}");
                    }
                }
            }

            return dataBuffer;
        }
        #endregion

        private static void ParseEncryptedChunk(ReadOnlySpan<byte> input, Span<byte> output, int chunkIndex)
        {
            var decryptedData = TryDecrypt(input, chunkIndex);
            
            // follow encoding of newly decrypted data
            switch ((char)decryptedData[0])
            {
                case 'N':
                    // Skip the compression mode byte, no discardOutput needed
                    ParseImmediate(decryptedData[1..], output, 0);
                    break;
                case 'Z':
                    // Skip the compression mode byte, no discardOutput needed  
                    ParseCompressed(decryptedData[1..], output, 0);
                    break;
                default:
                    throw new NotSupportedException($"Unsupported compression mode in encrypted chunk: {decryptedData[0]}");
            }
        }

        /// <summary>
        /// Based on the TACTSharp implementation
        /// </summary>
        private static Span<byte> TryDecrypt(ReadOnlySpan<byte> data, int chunkIndex)
        {
            static void ThrowInvalidDataFormat(string message) =>
                throw new ArgumentException($"Invalid encrypted chunk format: {message}", nameof(data));

            if (data.Length < 10) // Minimum: 1 keyNameSize + 8 keyName + 1 IVSize
                ThrowInvalidDataFormat("Insufficient data length for encrypted chunk header");

            var keyNameSize = data[0];
            if (keyNameSize != 8)
                ThrowInvalidDataFormat($"Expected key name size of 8 bytes, got {keyNameSize}");

            var keyName = BinaryPrimitives.ReadUInt64LittleEndian(data[1..9]);
            if (!TACTKeyService.TryGetKey(keyName, out var key))
                throw new DecryptionKeyMissingException(keyName);

            var ivSize = data[9];
            if (ivSize is not (4 or 16) || data.Length < 12 + ivSize)
                ThrowInvalidDataFormat($"Invalid IV size {ivSize} or insufficient data");

            // Copy IV data
            byte[] iv = data.Slice(10, ivSize).ToArray();
            Array.Resize(ref iv, 8);
            
            var encryptionTypeOffset = 10 + ivSize;
            if (data.Length <= encryptionTypeOffset)
                ThrowInvalidDataFormat("Missing encryption type indicator");

            var encryptionType = (char)data[encryptionTypeOffset];
            
            // Calculate data offset: keyNameSize(1) + keyName(8) + ivSize(1) + iv(N) + encType(1) = 1 + 8 + 1 + ivSize + 1
            int dataOffset = 1 + keyNameSize + 1 + ivSize + 1;
            
            if (data.Length <= dataOffset)
                ThrowInvalidDataFormat("No encrypted payload data found");

            // Apply chunk index XOR to IV
            for (int shift = 0, i = 0; i < sizeof(int); shift += 8, i++)
            {
                iv[i] ^= (byte)((chunkIndex >> shift) & 0xFF);
            }

            var encryptedDataLength = data.Length - dataOffset;
            return encryptionType switch
            {
                'S' => TACTKeyService.SalsaInstance
                    .CreateDecryptor(key, iv)
                    .TransformFinalBlock(data, dataOffset, encryptedDataLength),
                'A' => throw new NotSupportedException("ARC4 encryption is not implemented"),
                _ => throw new NotSupportedException($"Unknown encryption type: '{encryptionType}' (0x{(byte)encryptionType:X2})")
            };
        }

        /// <summary>
        /// Extracts the <paramref name="dataRange"/> bytes out of the <paramref name="resourceHandle"/>.
        /// </summary>
        /// <param name="resourceHandle"></param>
        /// <param name="dataRange">A range.</param>
        /// <returns>An </returns>
        public unsafe byte[] Execute(ResourceHandle resourceHandle, Range dataRange)
        {
            using var inputData = resourceHandle.ToMappedDataSource();

            var (_, decompressedLength) = dataRange.GetOffsetAndLength(_decompressedSize);
            var dataBuffer = GC.AllocateUninitializedArray<byte>(decompressedLength);

            for (var i = 0; i < _chunks.Length && decompressedLength != 0; ++i)
            {
                ref var currentChunk = ref _chunks[i];

                // Compute how many bytes we need to read in this chunk.
                var chunkRange = dataRange.Intersection(_decompressedSize, currentChunk.Decompressed);
                if (chunkRange.Equals(default)) // No overlap ?
                    continue;

                // Get the offset and length of data in this chunk.
                var (offset, length) = chunkRange.GetOffsetAndLength(currentChunk.DecompressedSize);

                // We read the whole input chunk because compressed chunks will need to discard.
                // Flat chunks will just copy-paste the data around.
                var input = inputData[currentChunk.Compressed];
                var output = dataBuffer.AsSpan().Slice(offset, length);

                if (currentChunk.IsEncrypted)
                {
                    // Decrypt the full chunk and copy
                    var tempOutput = GC.AllocateUninitializedArray<byte>(currentChunk.DecompressedSize);
                    ParseEncryptedChunk(input, tempOutput, i);
                    tempOutput.AsSpan().Slice(offset, length).CopyTo(output);
                }
                else
                {
                    currentChunk.Parser(input, output, offset);
                }
                
                // Update the remainder. It's faster to do this than re-calculating an intersection.
                decompressedLength -= length;
            }

            return dataBuffer;
        }

        /// <summary>
        /// Attempts to parse a BLTE schema out of the given span. 
        /// </summary>
        /// <typeparam name="K">The type of encoding key.</typeparam>
        /// <param name="fileData">A contiguous span of memory representing the file's data.</param>
        /// <param name="encodingKey">An encoding key that should match the calculated checksum of the file.</param>
        /// <param name="decompressedSize">The expected decompressed size of the file. If zero, this parameter is ignored</param>
        /// <remarks>
        /// If the checksum calculated does not match <paramref name="encodingKey"/>, <see langword="default" /> is returned.
        /// If the decompressed size does not match <paramref name="decompressedSize"/>, <see langword="default"/> is returned.
        /// </remarks>
        /// <returns>A schema that can then be used to parse a file.</returns>
        public unsafe static BLTE ParseSchema(ReadOnlySpan<byte> fileData, in Views.EncodingKey encodingKey, long decompressedSize = 0)
        {
            var (flags, chunks, expectedChecksum) = ParseHeader(fileData);
            EnsureSchemaValidity(chunks, decompressedSize);

            var checksumMatches = !encodingKey || encodingKey.SequenceEqual(expectedChecksum);
            var sizeMatches = decompressedSize != 0 && chunks[^1].Decompressed.End.Value == decompressedSize;

            if (chunks.Length == 0 || !checksumMatches || !sizeMatches)
                return default;

            return new BLTE(flags, chunks[^1].Decompressed.End.Value, chunks);
        }

        /// <summary>
        /// Attempts to parse a BLTE schema out of the given span. 
        /// </summary>
        /// <typeparam name="K">The type of encoding key.</typeparam>
        /// <param name="fileData">A contiguous span of memory representing the file's data.</param>
        /// <param name="decompressedSize">The expected decompressed size of the file. If zero, this parameter is ignored</param>
        /// <remarks>
        /// If the decompressed size does not match <paramref name="decompressedSize"/>, <see langword="default"/> is returned.
        /// </remarks>
        /// <returns>A schema that can then be used to parse a file.</returns>
        public unsafe static BLTE ParseSchema(ReadOnlySpan<byte> fileData, long decompressedSize = 0)
        {
            var (flags, chunks, _) = ParseHeader(fileData);
            EnsureSchemaValidity(chunks, decompressedSize);

            var sizeMatches = decompressedSize == 0 || chunks[^1].Decompressed.End.Value == decompressedSize;

            if (chunks.Length == 0 || !sizeMatches)
                return default;

            return new (flags, chunks[^1].Decompressed.End.Value, chunks);
        }

        /// <summary>
        /// Attempts to parse a BLTE schema out of the given span. 
        /// </summary>
        /// <typeparam name="K">The type of encoding key.</typeparam>
        /// <param name="resourceHandle">A handle over a resource.</param>
        /// <param name="encodingKey">An encoding key that should match the calculated checksum of the file.</param>
        /// <param name="decompressedSize">The expected decompressed size of the file. If zero, this parameter is ignored</param>
        /// <remarks>
        /// If the checksum calculated does not match <paramref name="encodingKey"/>, <see langword="default" /> is returned.
        /// If the decompressed size does not match <paramref name="decompressedSize"/>, <see langword="default"/> is returned.
        /// </remarks>
        /// <returns>A schema that can then be used to parse a file.</returns>
        public static BLTE ParseSchema(ResourceHandle resourceHandle, in Views.EncodingKey encodingKey, long decompressedSize)
        {
            using var memoryManager = resourceHandle.ToMappedDataSource();

            return ParseSchema(memoryManager[..], encodingKey, decompressedSize);
        }

        [Conditional("DEBUG")]
        private static void EnsureSchemaValidity(ChunkInfo[] chunks, long decompressedSize)
        {
            if (decompressedSize != 0)
                Debug.Assert(chunks.Aggregate(0L, (n, c) => n + c.DecompressedSize) == decompressedSize, "Mismatched size");

            for (var i = 1; i < chunks.Length; ++i)
            {
                ref var previousChunk = ref chunks[i - 1];
                ref var currentChunk = ref chunks[i];

                Debug.Assert(previousChunk.Compressed.End.Value + 1 == currentChunk.Compressed.Start.Value, "Hole found in compressed bytes according to generated schema");
                Debug.Assert(previousChunk.Decompressed.End.Value == currentChunk.Decompressed.Start.Value, "Hole found in decompressed bytes according to generated schema");
            }
        }

        #region Individual block parsers
        private static void ParseImmediate(ReadOnlySpan<byte> input, Span<byte> output, int discardCount)
            => input.Slice(discardCount, output.Length).CopyTo(output);

        private static void ParseCompressed(ReadOnlySpan<byte> input, Span<byte> output, int discardCount)
            => CompressionSlow.Instance.Decompress(input, output, discardCount, windowBits: 15);
        #endregion

        /// <summary>
        /// Reads the BLTE header from the given data source.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="fileData"></param>
        /// <param name="compressedBase"></param>
        /// <param name="decompressedBase"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe (int, List<ChunkInfo>, EncodingKey) ParseHeader<T>(T fileData, int compressedBase, int decompressedBase)
            where T : IDataSource, allows ref struct
        {
            var magic = fileData[..4];
            if (!magic.SequenceEqual([(byte)'B', (byte)'L', (byte)'T', (byte)'E']))
                return (0, [], default);

            var headerSize = fileData[4..].ReadInt32BE();
            var flagsChunkCount = fileData[8..].ReadUInt32BE();

            var expectedChecksum = MD5.HashData(fileData[..headerSize]);

            var flags = (int)flagsChunkCount >> 24;
            var chunkCount = (int)(flagsChunkCount & 0x00FFFFFFu);

            var chunks = new List<ChunkInfo>(chunkCount);

            var compressedStart = headerSize + compressedBase;
            var decompressedStart = decompressedBase;

            var chunkData = fileData.Slice(12, chunkCount * (4 + 4 + 16)).WithStride(4 + 4 + 16);
            for (var i = 0; i < chunkCount; ++i)
            {
                var chunkCompressedSize = chunkData[i].ReadInt32BE();
                var chunkDecompressedSize = chunkData[i][4..].ReadInt32BE();
                _ = chunkData[i].Slice(4 + 4, 16); // Checksum. TODO: Validate?

                Range compressedRange = new(compressedStart + 1, compressedStart + chunkCompressedSize);
                Range decompressedRange = new(decompressedStart, decompressedStart + chunkDecompressedSize);

                chunks.Add(new(compressedRange, decompressedRange, null));

                compressedStart = compressedRange.End.Value;
                decompressedStart = decompressedRange.End.Value;
            }

            return (flags, chunks, new EncodingKey(expectedChecksum));
        }

        private static unsafe (int, ChunkInfo[], EncodingKey) ParseHeader(ReadOnlySpan<byte> fileData, int compressedBase = 0, int decompressedBase = 0)
        {
            var (flags, chunks, encodingKey) = ParseHeader(fileData.ToDataSource(), compressedBase, decompressedBase);
            if (flags == 0)
                return (flags, [], default);

            // This is another loop that abuses cache locality
            // but also has special logic to flatten BLTE nested chunks.
            for (var i = 0; i < chunks.Count; ++i)
            {
                // Because Span's indexer still does bounds checking.
                ref var currentChunk = ref Unsafe.Add(ref MemoryMarshal.GetReference(CollectionsMarshal.AsSpan(chunks)), i);

                var compressionMode = fileData[currentChunk.Compressed.Start.Value - 1];
                switch (compressionMode)
                {
                    case (byte)'N':
                        currentChunk.Parser = &ParseImmediate;
                        break;
                    case (byte)'Z':
                        currentChunk.Parser = &ParseCompressed;
                        break;
                    case (byte)'E':
                        // For encrypted chunks, we'll set the parser to null and mark as encrypted
                        // The actual decryption and parsing will happen at read time
                        currentChunk.Parser = null;
                        currentChunk.IsEncrypted = true;
                        break;
                    case (byte)'F':
                        var (_, nestedChunks, _) = ParseHeader(fileData[currentChunk.Compressed], currentChunk.Compressed.Start.Value, currentChunk.Decompressed.Start.Value);

                        // Copy-insert everything - Not using RemoveAt + InsertRange because...
                        // One regrow, two memmoves. More efficient on codegen (one less memmove incurred by RemoveAt)

                        chunks.Capacity = chunks.Count + nestedChunks.Length - 1; // 1. Reallocate if necessary (one chunk will get written over)
                        var targetSpan = CollectionsMarshal.AsSpan(chunks);
                        targetSpan[(i + 1)..].CopyTo(targetSpan[(i + nestedChunks.Length)..]);  // 2. Move any chunk after this one ahead
                        nestedChunks.AsSpan().CopyTo(targetSpan.Slice(i, nestedChunks.Length)); // 3. And insert the new ones, overwriting the current object in the process.

                        i += nestedChunks.Length - 1; // Skip past the inserted chunks.
                        break;
                    default:
                        throw new IndexOutOfRangeException(nameof(compressionMode));
                }
            }

            return (flags, [.. chunks], encodingKey);
        }

        [DebuggerDisplay("{DebuggerDisplay,nq}")]
        internal unsafe struct ChunkInfo(Range compressed, Range decompressed,
            delegate*<ReadOnlySpan<byte>, Span<byte>, int, void> parser)
        {
            public readonly Range Compressed = compressed;
            public readonly Range Decompressed = decompressed;

            public delegate*<ReadOnlySpan<byte>, Span<byte>, int /* discardOutput */, void> Parser = parser;
            
            public bool IsEncrypted = false;
            public ulong EncryptionKeyName;
            public byte[]? EncryptionIV;

            public readonly int CompressedSize => Compressed.End.Value - Compressed.Start.Value;
            public readonly int DecompressedSize => Decompressed.End.Value - Decompressed.Start.Value;

            internal readonly string DebuggerDisplay => $"{Compressed} -> {Decompressed}";
        }
    }

    public class DecryptionKeyMissingException(ulong key) : Exception($"Decryption failed, key '{key:X16}' missing")
    {
        public ulong ExpectedKey { get; } = key;
        public string ExpectedKeyString => ExpectedKey.ToString("X16");
    }
}
