namespace ProjekatZastita.Services
{
    /// ovo je servis za automatsko pracenje foldera i pokretanje enkripcije kada se pojavi novi fajl
    /// povezuje FileSystemWatcher, Logger, FileEncryptionService i UI notifikaciju
    /// prati Target folder, detektuje Created, Changed, Renamed, Deleted 
    public class FileSystemWatcherService
    {
        private FileSystemWatcher? _watcher;
        private readonly Logger _logger;
        private readonly FileEncryptionService _encryptionService;
        private readonly string _targetDirectory;
        private readonly string _encryptedDirectory;

        //retry parametri - jer FSW cesto reaguje dok je fajl jos u pisanju, pa je zato uvedem retry mehanizam
        private const int RetryDelayMs   = 300;
        private const int MaxRetries      = 5;

        public event Action<string>? FileDetected; //omogucava UI-ju da dobije notifikaciju

        public FileSystemWatcherService(string targetDirectory, string encryptedDirectory,
            Logger logger, FileEncryptionService encryptionService)
        {
            _targetDirectory    = targetDirectory;
            _encryptedDirectory = encryptedDirectory;
            _logger             = logger;
            _encryptionService  = encryptionService;
        }

        public void Start()
        {
            if (_watcher != null) Stop();

            if (!Directory.Exists(_targetDirectory))
                Directory.CreateDirectory(_targetDirectory);

            _watcher = new FileSystemWatcher(_targetDirectory)
            {
                Filter = "*.*", 
                NotifyFilter = NotifyFilters.FileName  //reaguje na kreiranje fajla, promenu imena, promenu velicine, promenu vremena pisanja
                             | NotifyFilters.CreationTime
                             | NotifyFilters.LastWrite
                             | NotifyFilters.Size,
                EnableRaisingEvents = true,
                IncludeSubdirectories = false
            };

            _watcher.Created  += OnFileCreated;
            _watcher.Changed  += OnFileChanged;
            _watcher.Renamed  += OnFileRenamed;
            _watcher.Deleted  += OnFileDeleted;
            _watcher.Error    += OnWatcherError;

            _logger.Log($"[FSW] Started monitoring: {_targetDirectory}");
        }

        public void Stop()
        {
            if (_watcher == null) return;

            _watcher.EnableRaisingEvents = false;
            _watcher.Created  -= OnFileCreated;
            _watcher.Changed  -= OnFileChanged;
            _watcher.Renamed  -= OnFileRenamed;
            _watcher.Deleted  -= OnFileDeleted;
            _watcher.Error    -= OnWatcherError;
            _watcher.Dispose();
            _watcher = null;

            _logger.Log("[FSW] Stopped.");
        }

        // Event handlers

        private void OnFileCreated(object sender, FileSystemEventArgs e) //log, UI notifikacija, pokretanje enkripcije
        {
            _logger.Log($"[FSW] Created: {e.Name}");
            FileDetected?.Invoke(e.Name ?? string.Empty);
            EncryptWithRetry(e.FullPath);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e) =>  //samo loguje - zato vidimo sve Changed poruke
            _logger.Log($"[FSW] Changed: {e.Name}");

        private void OnFileRenamed(object sender, RenamedEventArgs e) =>  //loguje staro- novo ime
            _logger.Log($"[FSW] Renamed: {e.OldName} → {e.Name}");

        private void OnFileDeleted(object sender, FileSystemEventArgs e) =>  //loguje brisanja
            _logger.Log($"[FSW] Deleted: {e.Name}");

        private void OnWatcherError(object sender, ErrorEventArgs e) =>  //loguje sistemsku gresku
            _logger.Log($"[FSW] Error: {e.GetException().Message}");

        // Helpers

        private void EncryptWithRetry(string fullPath)
        {
            Task.Run(async () =>   //radi asinhrono, znaci ne blokira UI
            {
                for (int attempt = 1; attempt <= MaxRetries; attempt++)  //ako fajl nije dostupan, ceka i pokusava ponovo
                {
                    try
                    {
                        await Task.Delay(RetryDelayMs * attempt); //ide 300ms, 600ms, 900ms, ...

                        if (!File.Exists(fullPath)) return;

                        using (var _ = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.None)) { }

                        string safeName = Path.GetFileNameWithoutExtension(fullPath);
                        string outputPath = Path.Combine(_encryptedDirectory,
                            $"enc_{safeName}_{DateTime.Now:yyyyMMddHHmmss}.enc");

                        _encryptionService.EncryptFile(fullPath, outputPath, _logger);
                        return;
                    }
                    catch (IOException) when (attempt < MaxRetries)
                    {
                        // ako je fajl jos uve zakljucan - pokusaj ponovo
                    }
                    catch (Exception ex)
                    {
                        _logger.Log($"[FSW] Encrypt error for {Path.GetFileName(fullPath)}: {ex.Message}");
                        return;
                    }
                }

                _logger.Log($"[FSW] Could not access {Path.GetFileName(fullPath)} after {MaxRetries} attempts.");
            });
        }
    }
}
