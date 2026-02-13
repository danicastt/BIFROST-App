using System.Text.Json;
using System.Text.RegularExpressions;
using ProjekatZastita.Crypto;
using ProjekatZastita.Models;

namespace ProjekatZastita.Services
{
    /// ovo je centralna klasa koja implementira enkripciju i dekripciju fajlova u OFB rezimu rada koristeći RC6 i Bifid algoritme
    /// sistem koristi streaming obradu u 64KB blokovima radi efikasnosti, a integritet podataka se proverava pomoću SHA-1 heš funkcije koja se cuva 
    /// ovo je centralna klasa koja implementira enkripciju i dekripciju fajlova u OFB rezimu rada koristeći RC6 i Bifid algoritme
    //u JSON metapodacima na početku fajla.
    public class FileEncryptionService
    {
        public enum EncryptionAlgorithm
        {
            RC6_OFB = 0,
            Bifid_OFB = 1,
            RC6_Bifid_OFB = 2
        }

        private const int ChunkSize = 65_536; // velicina bloka - 64 KB za velike fajlove

        private readonly string _encryptedFilesPath;
        private byte[] _key;
        private EncryptionAlgorithm _algorithm;

        public FileEncryptionService(string encryptedFilesPath, byte[] key, EncryptionAlgorithm algorithm)
        {
            _encryptedFilesPath = encryptedFilesPath;
            _key = key;
            _algorithm = algorithm;

            if (!Directory.Exists(_encryptedFilesPath))
                Directory.CreateDirectory(_encryptedFilesPath);
        }

        // public API 

        public void EncryptFile(string sourcePath, string outputPath, Logger logger)
        {
            try
            {
                logger.Log($"Encrypting: {Path.GetFileName(sourcePath)} [{_algorithm}]");

                string ext  = Path.GetExtension(sourcePath);
                string mime = GetMimeType(ext);
                string hash;

                // na originalnom fajlu se primenjuje SHA-1
                using (var fs = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    hash = SHA1Helper.ComputeHash(fs);

                long fileSize = new FileInfo(sourcePath).Length;

                var metadata = new FileMetadata
                {
                    FileName           = Path.GetFileName(sourcePath),
                    OriginalExtension  = ext,
                    FileSize           = fileSize,
                    CreatedDate        = File.GetCreationTime(sourcePath),
                    EncryptedDate      = DateTime.Now,
                    Algorithm          = _algorithm.ToString(),
                    Mode               = "OFB",
                    HashAlgorithm      = "SHA1", //hash se ubacuje u metadata
                    Hash               = hash, // --
                    MimeType           = mime,
                    ChunkSize          = ChunkSize,
                    Version            = "2.0"
                };
                //deo gde se metadata zapisuje u fajl
                string jsonMeta    = JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true });
                byte[] metaBytes   = System.Text.Encoding.UTF8.GetBytes(jsonMeta);

                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

                using var outStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

                // pise metadata header
                outStream.Write(BitConverter.GetBytes(metaBytes.Length), 0, 4);
                outStream.Write(metaBytes, 0, metaBytes.Length);

              
                IStreamCipher cipher = CreateCipher(); //kreira se novi chiper
                byte[] buffer = new byte[ChunkSize];

                using var inStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                int read;
                while ((read = inStream.Read(buffer, 0, buffer.Length)) > 0) //stream obrada
                {
                    byte[] chunk = read == buffer.Length ? buffer : buffer[..read];
                    cipher.Transform(chunk, 0, read);
                    outStream.Write(chunk, 0, read);
                }

                logger.Log($"Encrypted → {Path.GetFileName(outputPath)} ({fileSize:N0} bytes, SHA1: {hash[..8]}…)");
            }
            catch (Exception ex)
            {
                logger.Log($"Encrypt error: {ex.Message}");
                throw;
            }
        }

        public DecryptionResult DecryptFile(string filePath, string outputDirectory, Logger logger)
        {
            try
            {
                logger.Log($"Decrypting: {Path.GetFileName(filePath)}");

                using var inStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var (metadata, payloadStart) = ReadMetadata(inStream);

                Directory.CreateDirectory(outputDirectory);
                string outputPath = Path.Combine(outputDirectory, metadata.FileName);

                IStreamCipher cipher = CreateCipher(); //kreira se odabrani chiper
                byte[] buffer       = new byte[ChunkSize];

                using var sha    = System.Security.Cryptography.SHA1.Create();
                long remaining   = inStream.Length - payloadStart;

                using var outFs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(buffer.Length, remaining);
                    int read   = inStream.Read(buffer, 0, toRead);
                    if (read == 0) break;

                    cipher.Transform(buffer, 0, read);
                    sha.TransformBlock(buffer, 0, read, null, 0);
                    outFs.Write(buffer, 0, read);
                    remaining -= read; //isto stream obrada
                }
                //ovde je deo gde se zavrsava racunanje SHA-1 nad dekriptovanim podacima, dobija konacan hesh i poredi sa hesh-om iz metoda
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                string computedHash = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
                bool   hashValid    = string.Equals(computedHash, metadata.Hash, StringComparison.OrdinalIgnoreCase); //proverava se hash

                if (!hashValid)
                    logger.Log($" Hash mismatch for {metadata.FileName}. Expected {metadata.Hash[..8]}…, got {computedHash[..8]}…");
                else
                    logger.Log($"Decrypted & verified: {metadata.FileName} (SHA1: {computedHash[..8]}…)");

                return new DecryptionResult(metadata, outputPath, hashValid);
            }
            catch (Exception ex)
            {
                logger.Log($"Decrypt error: {ex.Message}");
                throw;
            }
        }

        public DecryptionResult DecryptFromMemory(byte[] encryptedData, string outputDirectory, Logger logger)
        {
            using var ms = new MemoryStream(encryptedData);
            var (metadata, payloadStart) = ReadMetadata(ms);

            Directory.CreateDirectory(outputDirectory);
            string outputPath = Path.Combine(outputDirectory, metadata.FileName);

            IStreamCipher cipher = CreateCipher(); //kreira se novi chiper
            byte[] buffer        = new byte[ChunkSize];

            using var sha    = System.Security.Cryptography.SHA1.Create();
            long remaining   = ms.Length - payloadStart;

            using var outFs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            while (remaining > 0)
            {
                int toRead = (int)Math.Min(buffer.Length, remaining);
                int read   = ms.Read(buffer, 0, toRead);
                if (read == 0) break;

                cipher.Transform(buffer, 0, read);
                sha.TransformBlock(buffer, 0, read, null, 0);
                outFs.Write(buffer, 0, read);
                remaining -= read;
            }
            //ovde je deo gde se zavrsava racunanje SHA-1 nad dekriptovanim podacima, dobija konacan hesh i poredi sa hesh-om iz metoda
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            string computedHash = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
            bool   hashValid    = string.Equals(computedHash, metadata.Hash, StringComparison.OrdinalIgnoreCase);

            if (!hashValid)
                logger.Log($"Hash mismatch for {metadata.FileName}");
            else
                logger.Log($"Decrypted from network & verified: {metadata.FileName}");

            return new DecryptionResult(metadata, outputPath, hashValid);
        }

        // Helpers 
        //ovde biramo koji algoritam koristimo, tj bira se koji ce se chiper objekat napraviti 
        private IStreamCipher CreateCipher() => _algorithm switch
        {
            EncryptionAlgorithm.RC6_OFB        => new RC6OFBStreamCipher(_key),
            EncryptionAlgorithm.Bifid_OFB      => new BifidOFBStreamCipher(_key),
            EncryptionAlgorithm.RC6_Bifid_OFB  => new BifidOFBStreamCipher(_key), 
            _                                   => throw new NotSupportedException($"Unknown algorithm: {_algorithm}")
        };

        private static (FileMetadata metadata, long payloadStart) ReadMetadata(Stream stream)
        {
            byte[] lenBuf = new byte[4];
            stream.ReadExactly(lenBuf, 0, 4);
            int metaLen = BitConverter.ToInt32(lenBuf, 0);

            byte[] metaBytes = new byte[metaLen];
            stream.ReadExactly(metaBytes, 0, metaLen);

            var metadata = JsonSerializer.Deserialize<FileMetadata>(
                System.Text.Encoding.UTF8.GetString(metaBytes))
                ?? throw new InvalidDataException("Invalid metadata header.");

            return (metadata, stream.Position);
        }

        private static readonly Dictionary<string, string> MimeMap = new(StringComparer.OrdinalIgnoreCase)
        {
            [".txt"]  = "text/plain",
            [".pdf"]  = "application/pdf",
            [".png"]  = "image/png",
            [".jpg"]  = "image/jpeg",
            [".jpeg"] = "image/jpeg",
            [".gif"]  = "image/gif",
            [".bmp"]  = "image/bmp",
            [".zip"]  = "application/zip",
            [".rar"]  = "application/x-rar-compressed",
            [".7z"]   = "application/x-7z-compressed",
            [".mp3"]  = "audio/mpeg",
            [".mp4"]  = "video/mp4",
            [".avi"]  = "video/x-msvideo",
            [".doc"]  = "application/msword",
            [".docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            [".xls"]  = "application/vnd.ms-excel",
            [".xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            [".exe"]  = "application/octet-stream",
            [".bin"]  = "application/octet-stream",
        };

        private static string GetMimeType(string ext) =>
            MimeMap.TryGetValue(ext, out var mime) ? mime : "application/octet-stream";
    }
}
