namespace ProjekatZastita.Services
{
    /// servisna klasa koja zapisuje dogadjaje u fajl, obavestava UI da se pojavio novi log
    /// koristi se za enkripciju, dekripciju, mrezne operacije i greske (real-time prikaz logova)
    public class Logger
    {
        private readonly string _logFilePath; //putanja do log fajla
        private readonly object _lock = new(); //mora lock zato sto FSW, TCP listener, UI i enkripcija mogu da rade paralelno, pa da ne bi doslo do rance condition-a

        public event Action<string>? Logged; //event koji omogucava UI-ju da slusa logove

        public Logger(string logDirectory)
        {
            Directory.CreateDirectory(logDirectory); //ako folder ne postoji - kreira se
            _logFilePath = Path.Combine(logDirectory, $"log_{DateTime.Now:yyyy-MM-dd}.txt");
        }

        public void Log(string message)
        {
            string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";

            lock (_lock)
            {
                try { File.AppendAllText(_logFilePath, entry + Environment.NewLine); }
                catch { /* never let logging crash the app */ }
            }

            Logged?.Invoke(entry); //event poziv
        }

        public string GetLogPath() => _logFilePath;
    }
}
