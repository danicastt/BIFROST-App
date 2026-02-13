using System.Net;
using System.Net.Sockets;

namespace ProjekatZastita.Services
{
   
    public class NetworkService
    {
        private const int BufferSize = 65_536; // 64 KB

        private readonly Logger _logger;
        private readonly FileEncryptionService _encryptionService;

        public NetworkService(Logger logger, FileEncryptionService encryptionService)
        {
            _logger = logger;
            _encryptionService = encryptionService; //kada se primi fajl on mora da se dekriptuje i proveri hash
        }

        // Send 

        public async Task SendFileAsync(string filePath, string remoteHost, int port) //fajl se salje
        {
            try
            {
                string fileName = Path.GetFileName(filePath);
                long   fileSize = new FileInfo(filePath).Length;

                _logger.Log($"[TCP] Connecting to {remoteHost}:{port} …");

                using var client = new TcpClient();
                await client.ConnectAsync(remoteHost, port);
                using var stream = client.GetStream();

                _logger.Log($"[TCP] Connected. Sending '{fileName}' ({fileSize:N0} bytes).");

                // Write filename
                byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(fileName);
                await stream.WriteAsync(BitConverter.GetBytes(nameBytes.Length));
                await stream.WriteAsync(nameBytes);

                // upisuje fajl sa duzinom 8-byte 
                await stream.WriteAsync(BitConverter.GetBytes(fileSize));

                // Stream file data
                byte[] buffer = new byte[BufferSize];
                long sent     = 0;

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                                              BufferSize, FileOptions.SequentialScan);
                int read;
                while ((read = await fs.ReadAsync(buffer.AsMemory(0, BufferSize))) > 0)
                {
                    await stream.WriteAsync(buffer.AsMemory(0, read));
                    sent += read;
                }

                await stream.FlushAsync();
                _logger.Log($"[TCP] Sent '{fileName}' ({sent:N0} bytes) to {remoteHost}:{port}.");
            }
            catch (Exception ex)
            {
                _logger.Log($"[TCP] Send error: {ex.Message}");
                throw;
            }
        }

        // Listen

        public async Task ListenForFilesAsync(int port, string encryptedSavePath, string decryptedSavePath,
                                              CancellationToken cancellationToken = default) //fajl se prima
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            _logger.Log($"[TCP] Listening on port {port}.");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
                        string remote    = ((IPEndPoint?)client.Client.RemoteEndPoint)?.ToString() ?? "unknown";
                        _logger.Log($"[TCP] Connection accepted from {remote}.");
                        _ = HandleClientAsync(client, encryptedSavePath, decryptedSavePath, remote);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex) { _logger.Log($"[TCP] Accept error: {ex.Message}"); }
                }
            }
            finally
            {
                listener.Stop();
                _logger.Log($"[TCP] Listener stopped on port {port}.");
            }
        }


        private async Task HandleClientAsync(TcpClient client, string encryptedSavePath, //fajl se snima i dekriptuje
                                              string decryptedSavePath, string remote)
        {
            try
            {
                using (client)
                using (var stream = client.GetStream())
                {
                    // citanje filename
                    byte[] lenBuf = new byte[4];
                    await stream.ReadExactlyAsync(lenBuf);
                    int nameLen    = BitConverter.ToInt32(lenBuf, 0);
                    byte[] nameBuf = new byte[nameLen];
                    await stream.ReadExactlyAsync(nameBuf);
                    string fileName = System.Text.Encoding.UTF8.GetString(nameBuf);

                    // cita velicinu fajla (duzina 8-byte)
                    byte[] sizeBuf = new byte[8];
                    await stream.ReadExactlyAsync(sizeBuf);
                    long fileSize  = BitConverter.ToInt64(sizeBuf, 0);

                    _logger.Log($"[TCP] Receiving '{fileName}' ({fileSize:N0} bytes) from {remote}.");

                    // cuva enkriptovani fajl na disku
                    Directory.CreateDirectory(encryptedSavePath);
                    string encPath = Path.Combine(encryptedSavePath, $"recv_{fileName}");

                    long received = 0;
                    byte[] buffer = new byte[BufferSize];

                    using (var fs = new FileStream(encPath, FileMode.Create, FileAccess.Write, FileShare.None,
                                                   BufferSize, FileOptions.SequentialScan))
                    {
                        while (received < fileSize)
                        {
                            int toRead = (int)Math.Min(BufferSize, fileSize - received);
                            int read   = await stream.ReadAsync(buffer.AsMemory(0, toRead));
                            if (read == 0) throw new EndOfStreamException("Connection closed unexpectedly.");
                            await fs.WriteAsync(buffer.AsMemory(0, read));
                            received += read;
                        }
                    }

                    _logger.Log($"[TCP] Received '{fileName}' ({received:N0} bytes). Decrypting…");

                    // dekriptovanje sacuvanog fajla
                    try
                    {
                        var result = _encryptionService.DecryptFile(encPath, decryptedSavePath, _logger);
                        if (result.HashValid)
                            _logger.Log($"[TCP] Decrypted & verified: {result.OutputPath}");
                        else
                            _logger.Log($"[TCP] Hash mismatch: {result.Metadata?.FileName}");
                    }
                    catch (Exception ex)
                    {
                        _logger.Log($"[TCP] Decrypt error for '{fileName}': {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Log($"[TCP] Client handler error ({remote}): {ex.Message}");
            }
        }
    }
}
