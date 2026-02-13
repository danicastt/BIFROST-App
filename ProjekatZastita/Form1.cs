using ProjekatZastita.Services;
using ProjekatZastita.Utils;

namespace ProjekatZastita
{
    public partial class Form1 : Form
    {
        private const int DefaultPort = 5000;
        private const int KeyLength   = 16;

        private Logger _logger = null!;
        private FileEncryptionService _encryptionService = null!;
        private FileSystemWatcherService _fswService = null!;
        private NetworkService _networkService = null!;
        private CancellationTokenSource? _listenerCts;

        private readonly string _workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ProjekatZastita");
        private string _targetDir;
        private readonly string _encryptedDir;
        private readonly string _decryptedDir;
        private readonly string _logsDir;

        // kontroleri su definisani ovde tako da even hendleri mogu da ih referenciraju
        private ComboBox comboAlgorithm = null!;
        private TextBox txtKey = null!;
        private Button btnGenerateKey = null!;
        private Button btnApplySettings = null!;
        private Button btnEncrypt = null!;
        private Button btnDecrypt = null!;
        private Button btnSend = null!;
        private Button btnStartListen = null!;
        private Button btnStopListen = null!;
        private CheckBox chkFSW = null!;
        private TextBox txtRemoteHost = null!;
        private NumericUpDown numPortSend = null!;
        private NumericUpDown numPortListen = null!;
        private TextBox txtTargetDir = null!;
        private TextBox txtEncryptedDir = null!;
        private TextBox txtDecryptedDir = null!;
        private TextBox txtLogs = null!;
        private Button btnBrowseTarget = null!;
        private Button btnOpenEncrypted = null!;
        private Button btnOpenDecrypted = null!;

        public Form1()
        {
            InitializeComponent();

            _targetDir    = Path.Combine(_workDir, "Target");
            _encryptedDir = Path.Combine(_workDir, "Encrypted");
            _decryptedDir = Path.Combine(_workDir, "Decrypted");
            _logsDir      = Path.Combine(_workDir, "Logs");

            BuildUI();
            InitializeApp();
        }

        // UI kontrukcija

        private void BuildUI()
        {
            this.Text            = "BIFROST";
            this.StartPosition   = FormStartPosition.CenterScreen;
            this.ClientSize      = new Size(1200, 720);
            this.BackColor       = Color.FromArgb(245, 247, 250);
            this.ForeColor       = Color.FromArgb(30, 30, 30);
            this.Font            = new Font("Segoe UI", 10);

            // Header bar 
            var panelTop = new Panel
            {
                Dock      = DockStyle.Top,
                Height    = 60,
                BackColor = Color.FromArgb(30, 56, 92),
                Padding   = new Padding(16, 8, 16, 8)
            };
            var lblTitle = new Label
            {
                Dock      = DockStyle.Left,
                Text      = "BIFROST – Secure File Exchange",
                AutoSize  = true,
                Font      = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.White
            };
            // linija sa nazivom algoritama
            var lblAlgoBadge = new Label
            {
                Dock      = DockStyle.Right,
                Text      = "SHA-1 | Bifid | RC6 | OFB",
                AutoSize  = true,
                Font      = new Font("Segoe UI", 10, FontStyle.Italic),
                ForeColor = Color.FromArgb(180, 210, 255)
            };
            panelTop.Controls.Add(lblAlgoBadge);
            panelTop.Controls.Add(lblTitle);

            // glavni panel
            var panelMain = new Panel
            {
                Dock       = DockStyle.Fill,
                Padding    = new Padding(16),
                BackColor  = Color.FromArgb(245, 247, 250)
            };

            // coontrols panel 
            var panelControls = new Panel
            {
                Dock       = DockStyle.Top,
                Height     = 250,
                BackColor  = Color.FromArgb(236, 241, 247),
                Padding    = new Padding(14)
            };

            // Row 1 – Algorithm + Key
            var lblAlgorithm = new Label { Left = 10, Top = 12, Width = 120, Text = "Algorithm:" };
            comboAlgorithm = new ComboBox
            {
                Left           = 130,
                Top            = 8,
                Width          = 200,
                DropDownStyle  = ComboBoxStyle.DropDownList,
                BackColor      = Color.White,
                ForeColor      = Color.Black
            };
            comboAlgorithm.Items.AddRange(new[] { "RC6 (OFB)", "Bifid (OFB)", "RC6 + Bifid (OFB)" });
            comboAlgorithm.SelectedIndex = 0;
            comboAlgorithm.SelectedIndexChanged += (_, _) => InitializeEncryption();

            var lblKey = new Label { Left = 350, Top = 12, Width = 80, Text = "Key:" };
            txtKey = new TextBox
            {
                Left      = 430,
                Top       = 8,
                Width     = 260,
                BackColor = Color.White,
                ForeColor = Color.Black,
                Text      = "DefaultKey123456"
            };

            btnGenerateKey = new Button
            {
                Left      = 700,
                Top       = 7,
                Width     = 120,
                Height    = 28,
                Text      = "Generate",
                BackColor = Color.FromArgb(0, 120, 150),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnGenerateKey.Click += (_, _) =>
            {
                txtKey.Text = KeyUtils.GenerateReadableKey(KeyLength);
                InitializeEncryption();
            };

            btnApplySettings = new Button
            {
                Left      = 830,
                Top       = 7,
                Width     = 120,
                Height    = 28,
                Text      = "Apply",
                BackColor = Color.FromArgb(88, 90, 94),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnApplySettings.Click += (_, _) => InitializeEncryption();

            // Row 2 – FSW + Target Dir
            chkFSW = new CheckBox
            {
                Left      = 10,
                Top       = 50,
                Width     = 220,
                Text      = "Enable FSW Monitoring",
                ForeColor = Color.FromArgb(30, 30, 30),
                BackColor = Color.FromArgb(236, 241, 247)
            };
            chkFSW.CheckedChanged += (_, _) =>
            {
                if (chkFSW.Checked) _fswService.Start();
                else                _fswService.Stop();
            };

            var lblTarget = new Label { Left = 250, Top = 50, Width = 100, Text = "Target Dir:" };
            txtTargetDir = new TextBox
            {
                Left      = 340,
                Top       = 46,
                Width     = 350,
                ReadOnly  = true,
                BackColor = Color.White,
                ForeColor = Color.Black
            };
            btnBrowseTarget = new Button
            {
                Left      = 700,
                Top       = 45,
                Width     = 120,
                Height    = 26,
                Text      = "Change",
                BackColor = Color.FromArgb(0, 120, 150),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnBrowseTarget.Click += BtnBrowseTarget_Click;

            // Row 3 – Encrypted / Decrypted dirs
            var lblEncrypted = new Label { Left = 10, Top = 85, Width = 120, Text = "Encrypted Dir:" };
            txtEncryptedDir = new TextBox
            {
                Left      = 130,
                Top       = 81,
                Width     = 360,
                ReadOnly  = true,
                BackColor = Color.White,
                ForeColor = Color.Black
            };
            btnOpenEncrypted = new Button
            {
                Left      = 500,
                Top       = 80,
                Width     = 90,
                Height    = 26,
                Text      = "Open",
                BackColor = Color.FromArgb(88, 90, 94),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnOpenEncrypted.Click += (_, _) => OpenFolder(_encryptedDir);

            var lblDecrypted = new Label { Left = 600, Top = 85, Width = 120, Text = "Decrypted Dir:" };
            txtDecryptedDir = new TextBox
            {
                Left      = 720,
                Top       = 81,
                Width     = 300,
                ReadOnly  = true,
                BackColor = Color.White,
                ForeColor = Color.Black
            };
            btnOpenDecrypted = new Button
            {
                Left      = 1030,
                Top       = 80,
                Width     = 90,
                Height    = 26,
                Text      = "Open",
                BackColor = Color.FromArgb(88, 90, 94),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnOpenDecrypted.Click += (_, _) => OpenFolder(_decryptedDir);

            // Row 4 – Encrypt / Decrypt / Send
            btnEncrypt = new Button
            {
                Left      = 10,
                Top       = 125,
                Width     = 160,
                Height    = 34,
                Text      = "Encrypt File",
                BackColor = Color.FromArgb(0, 120, 150),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnEncrypt.Click += BtnEncrypt_Click;

            btnDecrypt = new Button
            {
                Left      = 180,
                Top       = 125,
                Width     = 160,
                Height    = 34,
                Text      = "Decrypt File",
                BackColor = Color.FromArgb(88, 90, 94),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnDecrypt.Click += BtnDecrypt_Click;

            var lblHost = new Label { Left = 360, Top = 130, Width = 90, Text = "Remote IP:" };
            txtRemoteHost = new TextBox
            {
                Left      = 440,
                Top       = 126,
                Width     = 150,
                BackColor = Color.White,
                ForeColor = Color.Black,
                Text      = "127.0.0.1"
            };

            var lblPortSend = new Label { Left = 600, Top = 130, Width = 70, Text = "Port:" };
            numPortSend = new NumericUpDown
            {
                Left      = 650,
                Top       = 126,
                Width     = 90,
                Minimum   = 1,
                Maximum   = 65535,
                Value     = DefaultPort,
                BackColor = Color.White,
                ForeColor = Color.Black
            };

            btnSend = new Button
            {
                Left      = 750,
                Top       = 124,
                Width     = 140,
                Height    = 34,
                Text      = "Send File",
                BackColor = Color.FromArgb(22, 152, 92),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnSend.Click += BtnSend_Click;

            var lblPortListen = new Label { Left = 900, Top = 130, Width = 80, Text = "Listen:" };
            numPortListen = new NumericUpDown
            {
                Left      = 960,
                Top       = 126,
                Width     = 90,
                Minimum   = 1,
                Maximum   = 65535,
                Value     = DefaultPort,
                BackColor = Color.White,
                ForeColor = Color.Black
            };

            // Row 5 – Start/Stop Listen
            btnStartListen = new Button
            {
                Left      = 10,
                Top       = 170,
                Width     = 160,
                Height    = 34,
                Text      = "Start Listening",
                BackColor = Color.FromArgb(22, 152, 92),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnStartListen.Click += BtnStartListen_Click;

            btnStopListen = new Button
            {
                Left      = 180,
                Top       = 170,
                Width     = 160,
                Height    = 34,
                Text      = "Stop Listening",
                BackColor = Color.FromArgb(198, 59, 59),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Enabled   = false
            };
            btnStopListen.Click += BtnStopListen_Click;

            // dodavanje svih kontrolera u panelControls
            panelControls.Controls.AddRange(new Control[]
            {
                lblAlgorithm, comboAlgorithm,
                lblKey, txtKey, btnGenerateKey, btnApplySettings,
                chkFSW,
                lblTarget, txtTargetDir, btnBrowseTarget,
                lblEncrypted, txtEncryptedDir, btnOpenEncrypted,
                lblDecrypted, txtDecryptedDir, btnOpenDecrypted,
                btnEncrypt, btnDecrypt,
                lblHost, txtRemoteHost,
                lblPortSend, numPortSend, btnSend,
                lblPortListen, numPortListen,
                btnStartListen, btnStopListen
            });

            // Log panel
            var panelLogs = new Panel
            {
                Dock      = DockStyle.Fill,
                BackColor = Color.FromArgb(250, 250, 250),
                Padding   = new Padding(12)
            };
            var lblLogs = new Label
            {
                Dock      = DockStyle.Top,
                Height    = 22,
                Text      = "Activity Log",
                Font      = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(30, 30, 30)
            };
            txtLogs = new TextBox
            {
                Dock        = DockStyle.Fill,
                Multiline   = true,
                ScrollBars  = ScrollBars.Vertical,
                BackColor   = Color.White,
                ForeColor   = Color.Black,
                Font        = new Font("Consolas", 9),
                ReadOnly    = true,
                BorderStyle = BorderStyle.FixedSingle
            };

            panelLogs.Controls.Add(txtLogs);
            panelLogs.Controls.Add(lblLogs);

            panelMain.Controls.Add(panelLogs);
            panelMain.Controls.Add(panelControls);

            this.Controls.Add(panelMain);
            this.Controls.Add(panelTop);
        }

        // inicijalizacija

        private void InitializeApp()
        {
            foreach (var d in new[] { _workDir, _targetDir, _encryptedDir, _decryptedDir, _logsDir })
                Directory.CreateDirectory(d);

            txtTargetDir.Text    = _targetDir;
            txtEncryptedDir.Text = _encryptedDir;
            txtDecryptedDir.Text = _decryptedDir;

            _logger = new Logger(_logsDir);
            _logger.Logged += OnLogged;
            _logger.Log("Application started.");
            _logger.Log($"Algorithms: SHA-1 | Bifid | RC6 | OFB");
            _logger.Log($"Work directory: {_workDir}");

            InitializeEncryption();
        }

        private void InitializeEncryption()
        {
            try
            {
                var algorithm = (FileEncryptionService.EncryptionAlgorithm)comboAlgorithm.SelectedIndex;
                byte[] key    = KeyUtils.DeriveKey(txtKey.Text, KeyLength);

                bool restartWatcher = chkFSW.Checked;
                _fswService?.Stop();

                _encryptionService = new FileEncryptionService(_encryptedDir, key, algorithm);
                _fswService = new FileSystemWatcherService(_targetDir, _encryptedDir, _logger, _encryptionService);
                _fswService.FileDetected += name =>
                {
                    if (InvokeRequired) BeginInvoke(() => ShowDetectedMessage(name));
                    else ShowDetectedMessage(name);
                };

                _networkService = new NetworkService(_logger, _encryptionService);

                if (restartWatcher)
                    _fswService.Start();

                _logger.Log($"Settings applied – Algorithm: {algorithm}, Key hash: {KeyUtils.DeriveKey(txtKey.Text, 4).Select(b => b.ToString("X2")).Aggregate((a, b) => a + b)}…");
            }
            catch (Exception ex)
            {
                _logger?.Log($"Initialization error: {ex.Message}");
            }
        }

        // Button handlers 

        private void BtnBrowseTarget_Click(object? sender, EventArgs e)
        {
            using var fbd = new FolderBrowserDialog
            {
                SelectedPath  = _targetDir,
                Description   = "Select target directory for FSW monitoring"
            };

            if (fbd.ShowDialog() == DialogResult.OK && !string.IsNullOrWhiteSpace(fbd.SelectedPath))
            {
                _targetDir       = fbd.SelectedPath;
                txtTargetDir.Text = fbd.SelectedPath;
                _fswService?.Stop();
                _fswService = new FileSystemWatcherService(_targetDir, _encryptedDir, _logger, _encryptionService);
                _fswService.FileDetected += name =>
                {
                    if (InvokeRequired) BeginInvoke(() => ShowDetectedMessage(name));
                    else ShowDetectedMessage(name);
                };
                if (chkFSW.Checked) _fswService.Start();
            }
        }

        private void BtnEncrypt_Click(object? sender, EventArgs e)
        {
            try
            {
                using var ofd = new OpenFileDialog
                {
                    Title  = "Select file to encrypt",
                    Filter = "All Files|*.*"
                };
                if (ofd.ShowDialog() != DialogResult.OK) return;

                string outputPath = Path.Combine(_encryptedDir,
                    $"enc_{Path.GetFileNameWithoutExtension(ofd.FileName)}_{DateTime.Now:yyyyMMddHHmmss}.enc");

                _encryptionService.EncryptFile(ofd.FileName, outputPath, _logger);
                MessageBox.Show($"File encrypted:\n{outputPath}", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                _logger.Log($"Encrypt error: {ex.Message}");
                MessageBox.Show($"Encryption failed:\n{ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnDecrypt_Click(object? sender, EventArgs e)
        {
            try
            {
                using var ofd = new OpenFileDialog
                {
                    Title  = "Select encrypted file",
                    Filter = "Encrypted Files|*.enc|All Files|*.*"
                };
                if (ofd.ShowDialog() != DialogResult.OK) return;

                var result = _encryptionService.DecryptFile(ofd.FileName, _decryptedDir, _logger);

                if (result.HashValid)
                {
                    MessageBox.Show(
                        $"File decrypted:\n{result.OutputPath}\n\nSHA-1 verified ✓",
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(
                        "SHA-1 hash verification FAILED.\nThe file may be corrupted or the wrong key was used.",
                        "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                _logger.Log($"Decrypt error: {ex.Message}");
                MessageBox.Show($"Decryption failed:\n{ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void BtnSend_Click(object? sender, EventArgs e)
        {
            try
            {
                using var ofd = new OpenFileDialog
                {
                    Title  = "Select file to encrypt & send",
                    Filter = "All Files|*.*"
                };
                if (ofd.ShowDialog() != DialogResult.OK) return;

                string encPath = Path.Combine(_encryptedDir,
                    $"enc_{Path.GetFileNameWithoutExtension(ofd.FileName)}_{DateTime.Now:yyyyMMddHHmmss}.enc");

                _encryptionService.EncryptFile(ofd.FileName, encPath, _logger);

                string host = txtRemoteHost.Text.Trim();
                int port    = (int)numPortSend.Value;

                await _networkService.SendFileAsync(encPath, host, port);
                MessageBox.Show($"File sent to {host}:{port}", "Sent",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                _logger.Log($"Send error: {ex.Message}");
                MessageBox.Show($"Sending failed:\n{ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void BtnStartListen_Click(object? sender, EventArgs e)
        {
            try
            {
                _listenerCts       = new CancellationTokenSource();
                btnStartListen.Enabled = false;
                btnStopListen.Enabled  = true;

                int port = (int)numPortListen.Value;
                _logger.Log($"Listening on port {port}…");

                await _networkService.ListenForFilesAsync(port, _encryptedDir, _decryptedDir, _listenerCts.Token);
            }
            catch (Exception ex)
            {
                _logger.Log($"Listen error: {ex.Message}");
            }
            finally
            {
                btnStartListen.Enabled = true;
                btnStopListen.Enabled  = false;
            }
        }

        private void BtnStopListen_Click(object? sender, EventArgs e)
        {
            _listenerCts?.Cancel();
            btnStartListen.Enabled = true;
            btnStopListen.Enabled  = false;
            _logger.Log("Listener stopped.");
        }

        // Helpers

        private void OpenFolder(string path)
        {
            try
            {
                if (Directory.Exists(path))
                    System.Diagnostics.Process.Start("explorer.exe", path);
            }
            catch (Exception ex)
            {
                _logger.Log($"Unable to open folder: {ex.Message}");
            }
        }

        private void ShowDetectedMessage(string fileName)
        {
            MessageBox.Show(
                $"New file detected:\n{fileName}\n\nThe file was automatically encrypted.",
                "FSW Notification", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void OnLogged(string entry)
        {
            if (InvokeRequired) { BeginInvoke(() => OnLogged(entry)); return; }
            txtLogs.AppendText(entry + Environment.NewLine);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _fswService?.Stop();
            _listenerCts?.Cancel();
            _logger?.Log("Application closed.");
            base.OnFormClosing(e);
        }
    }
}
