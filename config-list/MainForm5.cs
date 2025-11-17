using System;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Azure;
using Azure.Data.AppConfiguration;
using StackExchange.Redis;
using System.Collections.Generic;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace AzureAppConfigManager
{
    public partial class MainForm : Form
    {
        private ConfigurationClient _configClient;
        private ConnectionMultiplexer _redis;
        private IDatabase _redisDb;
        private SecretClient _keyVaultClient;

        private List<ConfigItem> _cachedConfigs = new List<ConfigItem>();
        private List<RedisItem> _cachedRedisItems = new List<RedisItem>();
        private List<KeyVaultItem> _cachedKeyVaultSecrets = new List<KeyVaultItem>();

        private MenuStrip menuStrip;
        private DataGridView dgvConfigs;
        private TextBox txtKey;
        private TextBox txtValue;
        private TextBox txtLabel;
        private TextBox txtFilter;
        private Button btnAdd;
        private Button btnRefresh;
        private Button btnFilter;
        private Button btnClearFilter;
        private Button btnCopyValue;
        private Button btnCopyKey;
        private Button btnUpdate;
        private Button btnDelete;
        private Label lblStatus;
        private Label lblFilterLabel;
        private Panel pnlAddConfig;
        private Panel pnlFilterPanel;

        private bool _isRedisMode = false;
        private bool _isKeyVaultMode = false;

        public MainForm()
        {
            InitializeComponent();
            InitializeAzureClient();
            LoadConfigurations();
        }

        private void InitializeComponent()
        {
            this.Text = "Azure App Configuration Manager";
            this.Size = new System.Drawing.Size(900, 680);
            this.StartPosition = FormStartPosition.CenterScreen;

            // Menu Strip
            menuStrip = new MenuStrip();

            ToolStripMenuItem dataSourceMenu = new ToolStripMenuItem("Data Source");
            ToolStripMenuItem appConfigMenu = new ToolStripMenuItem("Azure App Configuration");
            ToolStripMenuItem redisMenu = new ToolStripMenuItem("Redis Cache");
            ToolStripMenuItem keyVaultMenu = new ToolStripMenuItem("Azure Key Vault");

            appConfigMenu.Click += AppConfigMenu_Click;
            redisMenu.Click += RedisMenu_Click;
            keyVaultMenu.Click += KeyVaultMenu_Click;

            dataSourceMenu.DropDownItems.Add(appConfigMenu);
            dataSourceMenu.DropDownItems.Add(redisMenu);
            dataSourceMenu.DropDownItems.Add(keyVaultMenu);
            menuStrip.Items.Add(dataSourceMenu);

            this.MainMenuStrip = menuStrip;
            this.Controls.Add(menuStrip);

            // Filter Panel
            pnlFilterPanel = new Panel
            {
                Location = new System.Drawing.Point(20, 50),
                Size = new System.Drawing.Size(840, 40),
                BorderStyle = BorderStyle.FixedSingle
            };

            lblFilterLabel = new Label
            {
                Text = "Filter Pattern:",
                Location = new System.Drawing.Point(5, 12),
                Size = new System.Drawing.Size(90, 20)
            };
            pnlFilterPanel.Controls.Add(lblFilterLabel);

            txtFilter = new TextBox
            {
                Location = new System.Drawing.Point(100, 10),
                Size = new System.Drawing.Size(300, 20),
                PlaceholderText = "e.g., MyApp:*, *Database*, Setting*"
            };
            txtFilter.KeyPress += TxtFilter_KeyPress;
            pnlFilterPanel.Controls.Add(txtFilter);

            btnFilter = new Button
            {
                Text = "Apply Filter",
                Location = new System.Drawing.Point(410, 8),
                Size = new System.Drawing.Size(100, 25)
            };
            btnFilter.Click += BtnFilter_Click;
            pnlFilterPanel.Controls.Add(btnFilter);

            btnClearFilter = new Button
            {
                Text = "Clear Filter",
                Location = new System.Drawing.Point(520, 8),
                Size = new System.Drawing.Size(100, 25)
            };
            btnClearFilter.Click += BtnClearFilter_Click;
            pnlFilterPanel.Controls.Add(btnClearFilter);

            // Add info label for Redis mode
            Label lblRedisInfo = new Label
            {
                Text = "For Redis: Filter loads only matching keys from server",
                Location = new System.Drawing.Point(630, 12),
                Size = new System.Drawing.Size(200, 20),
                ForeColor = System.Drawing.Color.Blue,
                Font = new System.Drawing.Font("Arial", 7.5f),
                Name = "lblRedisInfo",
                Visible = false
            };
            pnlFilterPanel.Controls.Add(lblRedisInfo);

            this.Controls.Add(pnlFilterPanel);

            // DataGridView for listing configurations
            dgvConfigs = new DataGridView
            {
                Location = new System.Drawing.Point(20, 100),
                Size = new System.Drawing.Size(840, 300),
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                ReadOnly = true,
                AllowUserToAddRows = false
            };
            dgvConfigs.SelectionChanged += DgvConfigs_SelectionChanged;
            this.Controls.Add(dgvConfigs);

            // Action buttons panel
            Panel pnlActions = new Panel
            {
                Location = new System.Drawing.Point(20, 410),
                Size = new System.Drawing.Size(840, 40)
            };

            btnCopyValue = new Button
            {
                Text = "Copy Value",
                Location = new System.Drawing.Point(0, 5),
                Size = new System.Drawing.Size(100, 30)
            };
            btnCopyValue.Click += BtnCopyValue_Click;
            pnlActions.Controls.Add(btnCopyValue);

            btnCopyKey = new Button
            {
                Text = "Copy Key",
                Location = new System.Drawing.Point(110, 5),
                Size = new System.Drawing.Size(100, 30)
            };
            btnCopyKey.Click += BtnCopyKey_Click;
            pnlActions.Controls.Add(btnCopyKey);

            btnUpdate = new Button
            {
                Text = "Update",
                Location = new System.Drawing.Point(220, 5),
                Size = new System.Drawing.Size(100, 30)
            };
            btnUpdate.Click += BtnUpdate_Click;
            pnlActions.Controls.Add(btnUpdate);

            btnDelete = new Button
            {
                Text = "Delete",
                Location = new System.Drawing.Point(330, 5),
                Size = new System.Drawing.Size(100, 30),
                ForeColor = System.Drawing.Color.Red
            };
            btnDelete.Click += BtnDelete_Click;
            pnlActions.Controls.Add(btnDelete);

            btnRefresh = new Button
            {
                Text = "Refresh from Source",
                Location = new System.Drawing.Point(700, 5),
                Size = new System.Drawing.Size(140, 30)
            };
            btnRefresh.Click += BtnRefresh_Click;
            pnlActions.Controls.Add(btnRefresh);

            this.Controls.Add(pnlActions);

            // Panel for Add Configuration section
            pnlAddConfig = new Panel
            {
                Location = new System.Drawing.Point(20, 460),
                Size = new System.Drawing.Size(840, 90),
                BorderStyle = BorderStyle.FixedSingle
            };

            // Add new configuration section
            Label lblAddNew = new Label
            {
                Text = "Add New Configuration:",
                Location = new System.Drawing.Point(5, 5),
                Size = new System.Drawing.Size(200, 20),
                Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Bold)
            };
            pnlAddConfig.Controls.Add(lblAddNew);

            // Key input
            Label lblKey = new Label
            {
                Text = "Key:",
                Location = new System.Drawing.Point(5, 35),
                Size = new System.Drawing.Size(80, 20)
            };
            pnlAddConfig.Controls.Add(lblKey);

            txtKey = new TextBox
            {
                Location = new System.Drawing.Point(85, 33),
                Size = new System.Drawing.Size(250, 20)
            };
            pnlAddConfig.Controls.Add(txtKey);

            // Value input
            Label lblValue = new Label
            {
                Text = "Value:",
                Location = new System.Drawing.Point(350, 35),
                Size = new System.Drawing.Size(80, 20)
            };
            pnlAddConfig.Controls.Add(lblValue);

            txtValue = new TextBox
            {
                Location = new System.Drawing.Point(430, 33),
                Size = new System.Drawing.Size(250, 20)
            };
            pnlAddConfig.Controls.Add(txtValue);

            // Label input (optional)
            Label lblLabelInput = new Label
            {
                Text = "Label:",
                Location = new System.Drawing.Point(5, 65),
                Size = new System.Drawing.Size(80, 20)
            };
            pnlAddConfig.Controls.Add(lblLabelInput);

            txtLabel = new TextBox
            {
                Location = new System.Drawing.Point(85, 63),
                Size = new System.Drawing.Size(250, 20)
            };
            pnlAddConfig.Controls.Add(txtLabel);

            // Add button
            btnAdd = new Button
            {
                Text = "Add Configuration",
                Location = new System.Drawing.Point(350, 60),
                Size = new System.Drawing.Size(150, 30)
            };
            btnAdd.Click += BtnAdd_Click;
            pnlAddConfig.Controls.Add(btnAdd);

            this.Controls.Add(pnlAddConfig);

            // Status label
            lblStatus = new Label
            {
                Text = "Ready",
                Location = new System.Drawing.Point(20, 560),
                Size = new System.Drawing.Size(840, 20),
                ForeColor = System.Drawing.Color.Green
            };
            this.Controls.Add(lblStatus);
        }

        private void InitializeAzureClient()
        {
            try
            {
                string connectionString = ConfigurationManager.AppSettings["AzureAppConfigConnectionString"];

                if (string.IsNullOrEmpty(connectionString))
                {
                    MessageBox.Show(
                        "Azure App Configuration connection string not found in App.config.\n\n" +
                        "Please add the following to your App.config:\n" +
                        "<appSettings>\n" +
                        "  <add key=\"AzureAppConfigConnectionString\" value=\"Your-Connection-String\" />\n" +
                        "</appSettings>",
                        "Configuration Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                _configClient = new ConfigurationClient(connectionString);
                UpdateStatus("Connected to Azure App Configuration", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing Azure client: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Connection failed", System.Drawing.Color.Red);
            }
        }

        private void InitializeRedisClient()
        {
            try
            {
                string connectionString = ConfigurationManager.AppSettings["RedisConnectionString"];

                if (string.IsNullOrEmpty(connectionString))
                {
                    MessageBox.Show(
                        "Redis connection string not found in App.config.\n\n" +
                        "Please add the following to your App.config:\n" +
                        "<appSettings>\n" +
                        "  <add key=\"RedisConnectionString\" value=\"Your-Redis-Connection-String\" />\n" +
                        "</appSettings>",
                        "Configuration Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                _redis = ConnectionMultiplexer.Connect(connectionString);
                _redisDb = _redis.GetDatabase();
                UpdateStatus("Connected to Redis Cache", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing Redis client: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Redis connection failed", System.Drawing.Color.Red);
            }
        }

        private void InitializeKeyVaultClient()
        {
            try
            {
                string keyVaultUrl = ConfigurationManager.AppSettings["KeyVaultUrl"];

                if (string.IsNullOrEmpty(keyVaultUrl))
                {
                    MessageBox.Show(
                        "Key Vault URL not found in App.config.\n\n" +
                        "Please add the following to your App.config:\n" +
                        "<appSettings>\n" +
                        "  <add key=\"KeyVaultUrl\" value=\"https://your-keyvault.vault.azure.net/\" />\n" +
                        "</appSettings>\n\n" +
                        "Make sure you're logged in via Azure CLI (az login) or have proper Azure credentials configured.",
                        "Configuration Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                // Use DefaultAzureCredential for authentication
                _keyVaultClient = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
                UpdateStatus("Connected to Azure Key Vault using Default Credentials", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing Key Vault client: {ex.Message}\n\n" +
                    "Make sure you're authenticated via Azure CLI (az login) or have proper credentials configured.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Key Vault connection failed", System.Drawing.Color.Red);
            }
        }

        private void AppConfigMenu_Click(object sender, EventArgs e)
        {
            _isRedisMode = false;
            _isKeyVaultMode = false;
            this.Text = "Azure App Configuration Manager";
            txtLabel.Visible = true;
            pnlFilterPanel.Visible = true;
            pnlAddConfig.Visible = true;
            pnlAddConfig.Controls.OfType<Label>().FirstOrDefault(l => l.Text == "Label:")?.Show();

            // Hide Redis-specific info
            var lblRedisInfo = pnlFilterPanel.Controls.Find("lblRedisInfo", false).FirstOrDefault();
            if (lblRedisInfo != null)
                lblRedisInfo.Visible = false;

            if (_configClient == null)
                InitializeAzureClient();

            // Load from cache if available, otherwise fetch from source
            if (_cachedConfigs.Count > 0)
            {
                DisplayFilteredConfigs("");
                UpdateStatus($"Showing {_cachedConfigs.Count} cached configuration(s) - Use 'Refresh from Source' to reload", System.Drawing.Color.Blue);
            }
            else
            {
                LoadConfigurations();
            }
        }

        private void RedisMenu_Click(object sender, EventArgs e)
        {
            _isRedisMode = true;
            _isKeyVaultMode = false;
            this.Text = "Redis Cache Manager";
            txtLabel.Visible = false;
            pnlFilterPanel.Visible = true;
            pnlAddConfig.Visible = true;
            pnlAddConfig.Controls.OfType<Label>().FirstOrDefault(l => l.Text == "Label:")?.Hide();

            // Show Redis-specific info
            var lblRedisInfo = pnlFilterPanel.Controls.Find("lblRedisInfo", false).FirstOrDefault();
            if (lblRedisInfo != null)
                lblRedisInfo.Visible = true;

            if (_redis == null)
                InitializeRedisClient();

            // For Redis, don't auto-load all keys - prompt user to filter or load
            if (_cachedRedisItems.Count > 0)
            {
                DisplayFilteredRedisItems("");
                UpdateStatus($"Showing {_cachedRedisItems.Count} cached Redis key(s) - Use filter or 'Refresh from Source'", System.Drawing.Color.Blue);
            }
            else
            {
                dgvConfigs.DataSource = null;
                UpdateStatus("Redis mode: Enter a pattern filter (e.g., MyApp:*) or click 'Refresh from Source' to load all keys", System.Drawing.Color.Blue);
            }
        }

        private void KeyVaultMenu_Click(object sender, EventArgs e)
        {
            _isRedisMode = false;
            _isKeyVaultMode = true;
            this.Text = "Azure Key Vault Manager";
            txtLabel.Visible = false;
            pnlFilterPanel.Visible = true;
            pnlAddConfig.Visible = true;
            pnlAddConfig.Controls.OfType<Label>().FirstOrDefault(l => l.Text == "Label:")?.Hide();

            // Hide Redis-specific info
            var lblRedisInfo = pnlFilterPanel.Controls.Find("lblRedisInfo", false).FirstOrDefault();
            if (lblRedisInfo != null)
                lblRedisInfo.Visible = false;

            if (_keyVaultClient == null)
                InitializeKeyVaultClient();

            // Load from cache if available, otherwise fetch from source
            if (_cachedKeyVaultSecrets.Count > 0)
            {
                DisplayFilteredKeyVaultSecrets("");
                UpdateStatus($"Showing {_cachedKeyVaultSecrets.Count} cached secret(s) - Use 'Refresh from Source' to reload", System.Drawing.Color.Blue);
            }
            else
            {
                LoadConfigurations();
            }
        }

        private async void LoadConfigurations()
        {
            if (_isKeyVaultMode)
            {
                await LoadKeyVaultSecrets();
            }
            else if (_isRedisMode)
            {
                await LoadRedisKeys();
            }
            else
            {
                await LoadAzureAppConfigs();
            }
        }

        private async Task LoadAzureAppConfigs()
        {
            if (_configClient == null) return;

            try
            {
                UpdateStatus("Loading configurations from Azure...", System.Drawing.Color.Blue);
                btnRefresh.Enabled = false;

                var configs = new List<ConfigItem>();

                await Task.Run(async () =>
                {
                    var selector = new SettingSelector();
                    await foreach (var setting in _configClient.GetConfigurationSettingsAsync(selector))
                    {
                        configs.Add(new ConfigItem
                        {
                            Key = setting.Key,
                            Value = setting.Value,
                            Label = setting.Label ?? "",
                            ContentType = setting.ContentType ?? "",
                            LastModified = setting.LastModified?.DateTime ?? DateTime.MinValue
                        });
                    }
                });

                _cachedConfigs = configs.OrderBy(c => c.Key).ToList();
                dgvConfigs.DataSource = _cachedConfigs.ToList();
                txtFilter.Clear();
                UpdateStatus($"Loaded and cached {_cachedConfigs.Count} configuration(s) from Azure", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading configurations: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to load configurations", System.Drawing.Color.Red);
            }
            finally
            {
                btnRefresh.Enabled = true;
            }
        }

        private async Task LoadRedisKeys()
        {
            if (_redis == null || _redisDb == null) return;

            try
            {
                UpdateStatus("Loading Redis keys...", System.Drawing.Color.Blue);
                btnRefresh.Enabled = false;

                var redisItems = new List<RedisItem>();

                await Task.Run(() =>
                {
                    var endpoints = _redis.GetEndPoints();
                    var server = _redis.GetServer(endpoints[0]);

                    // Use pageSize to limit memory usage for large key sets
                    var keys = server.Keys(pattern: "*", pageSize: 1000);

                    int count = 0;
                    foreach (var key in keys)
                    {
                        var value = _redisDb.StringGet(key);
                        var ttl = _redisDb.KeyTimeToLive(key);
                        var keyType = _redisDb.KeyType(key);

                        redisItems.Add(new RedisItem
                        {
                            Key = key.ToString(),
                            Value = value.HasValue ? value.ToString() : "(empty)",
                            Type = keyType.ToString(),
                            TTL = ttl.HasValue ? ttl.Value.ToString() : "No expiration"
                        });

                        count++;
                        if (count % 100 == 0)
                        {
                            // Update UI every 100 keys to show progress
                            this.Invoke((MethodInvoker)delegate
                            {
                                UpdateStatus($"Loading Redis keys... ({count} loaded)", System.Drawing.Color.Blue);
                            });
                        }
                    }
                });

                _cachedRedisItems = redisItems.OrderBy(r => r.Key).ToList();
                dgvConfigs.DataSource = _cachedRedisItems.ToList();
                txtFilter.Clear();
                UpdateStatus($"Loaded and cached {_cachedRedisItems.Count} Redis key(s)", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading Redis keys: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to load Redis keys", System.Drawing.Color.Red);
            }
            finally
            {
                btnRefresh.Enabled = true;
            }
        }

        private async Task LoadRedisKeysByPattern(string pattern)
        {
            if (_redis == null || _redisDb == null) return;

            try
            {
                UpdateStatus($"Loading Redis keys matching '{pattern}'...", System.Drawing.Color.Blue);
                btnFilter.Enabled = false;
                btnRefresh.Enabled = false;

                var redisItems = new List<RedisItem>();

                await Task.Run(() =>
                {
                    var endpoints = _redis.GetEndPoints();
                    var server = _redis.GetServer(endpoints[0]);

                    // Convert wildcard pattern to Redis pattern
                    // Our pattern: MyApp:* -> Redis pattern: MyApp:*
                    // This is already compatible, but ensure it's valid
                    string redisPattern = string.IsNullOrEmpty(pattern) ? "*" : pattern;

                    var keys = server.Keys(pattern: redisPattern, pageSize: 1000);

                    int count = 0;
                    foreach (var key in keys)
                    {
                        var value = _redisDb.StringGet(key);
                        var ttl = _redisDb.KeyTimeToLive(key);
                        var keyType = _redisDb.KeyType(key);

                        redisItems.Add(new RedisItem
                        {
                            Key = key.ToString(),
                            Value = value.HasValue ? value.ToString() : "(empty)",
                            Type = keyType.ToString(),
                            TTL = ttl.HasValue ? ttl.Value.ToString() : "No expiration"
                        });

                        count++;
                        if (count % 100 == 0)
                        {
                            this.Invoke((MethodInvoker)delegate
                            {
                                UpdateStatus($"Loading Redis keys matching '{pattern}'... ({count} loaded)", System.Drawing.Color.Blue);
                            });
                        }
                    }
                });

                _cachedRedisItems = redisItems.OrderBy(r => r.Key).ToList();
                dgvConfigs.DataSource = _cachedRedisItems.ToList();
                UpdateStatus($"Loaded {_cachedRedisItems.Count} Redis key(s) matching pattern '{pattern}'", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading Redis keys: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to load Redis keys", System.Drawing.Color.Red);
            }
            finally
            {
                btnFilter.Enabled = true;
                btnRefresh.Enabled = true;
            }
        }

        private async Task LoadKeyVaultSecrets()
        {
            if (_keyVaultClient == null) return;

            try
            {
                UpdateStatus("Loading Key Vault secrets...", System.Drawing.Color.Blue);
                btnRefresh.Enabled = false;

                var secrets = new List<KeyVaultItem>();

                await Task.Run(async () =>
                {
                    await foreach (var secretProperties in _keyVaultClient.GetPropertiesOfSecretsAsync())
                    {
                        try
                        {
                            // Get the actual secret value
                            var secret = await _keyVaultClient.GetSecretAsync(secretProperties.Name);

                            secrets.Add(new KeyVaultItem
                            {
                                Name = secretProperties.Name,
                                Value = secret.Value.Value,
                                ContentType = secretProperties.ContentType ?? "",
                                Enabled = secretProperties.Enabled ?? false,
                                CreatedOn = secretProperties.CreatedOn?.DateTime ?? DateTime.MinValue,
                                UpdatedOn = secretProperties.UpdatedOn?.DateTime ?? DateTime.MinValue
                            });
                        }
                        catch (Exception ex)
                        {
                            // If we can't read a specific secret, add it with error message
                            secrets.Add(new KeyVaultItem
                            {
                                Name = secretProperties.Name,
                                Value = $"[Error: {ex.Message}]",
                                ContentType = secretProperties.ContentType ?? "",
                                Enabled = secretProperties.Enabled ?? false,
                                CreatedOn = secretProperties.CreatedOn?.DateTime ?? DateTime.MinValue,
                                UpdatedOn = secretProperties.UpdatedOn?.DateTime ?? DateTime.MinValue
                            });
                        }
                    }
                });

                _cachedKeyVaultSecrets = secrets.OrderBy(s => s.Name).ToList();
                dgvConfigs.DataSource = _cachedKeyVaultSecrets.ToList();
                txtFilter.Clear();
                UpdateStatus($"Loaded and cached {_cachedKeyVaultSecrets.Count} secret(s) from Key Vault", System.Drawing.Color.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading Key Vault secrets: {ex.Message}\n\n" +
                    "Make sure you have proper permissions (Get, List) on the Key Vault secrets.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to load Key Vault secrets", System.Drawing.Color.Red);
            }
            finally
            {
                btnRefresh.Enabled = true;
            }
        }

        private void BtnFilter_Click(object sender, EventArgs e)
        {
            ApplyFilter();
        }

        private void TxtFilter_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Enter)
            {
                ApplyFilter();
                e.Handled = true;
            }
        }

        private async void ApplyFilter()
        {
            string pattern = txtFilter.Text.Trim();

            if (_isKeyVaultMode)
            {
                DisplayFilteredKeyVaultSecrets(pattern);
            }
            else if (_isRedisMode)
            {
                // For Redis, if there's a pattern and no cache, load directly from Redis with pattern
                if (!string.IsNullOrEmpty(pattern) && _cachedRedisItems.Count == 0)
                {
                    await LoadRedisKeysByPattern(pattern);
                }
                else
                {
                    // If we have cache, filter locally
                    DisplayFilteredRedisItems(pattern);
                }
            }
            else
            {
                DisplayFilteredConfigs(pattern);
            }
        }

        private void DisplayFilteredConfigs(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                dgvConfigs.DataSource = _cachedConfigs.ToList();
                UpdateStatus($"Showing all {_cachedConfigs.Count} configuration(s)", System.Drawing.Color.Green);
                return;
            }

            var filtered = _cachedConfigs.Where(c => MatchesPattern(c.Key, pattern)).ToList();
            dgvConfigs.DataSource = filtered;
            UpdateStatus($"Filter applied: Showing {filtered.Count} of {_cachedConfigs.Count} configuration(s)", System.Drawing.Color.Green);
        }

        private void DisplayFilteredRedisItems(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                dgvConfigs.DataSource = _cachedRedisItems.ToList();
                UpdateStatus($"Showing all {_cachedRedisItems.Count} Redis key(s)", System.Drawing.Color.Green);
                return;
            }

            var filtered = _cachedRedisItems.Where(r => MatchesPattern(r.Key, pattern)).ToList();
            dgvConfigs.DataSource = filtered;
            UpdateStatus($"Filter applied: Showing {filtered.Count} of {_cachedRedisItems.Count} Redis key(s)", System.Drawing.Color.Green);
        }

        private void DisplayFilteredKeyVaultSecrets(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                dgvConfigs.DataSource = _cachedKeyVaultSecrets.ToList();
                UpdateStatus($"Showing all {_cachedKeyVaultSecrets.Count} secret(s)", System.Drawing.Color.Green);
                return;
            }

            var filtered = _cachedKeyVaultSecrets.Where(s => MatchesPattern(s.Name, pattern)).ToList();
            dgvConfigs.DataSource = filtered;
            UpdateStatus($"Filter applied: Showing {filtered.Count} of {_cachedKeyVaultSecrets.Count} secret(s)", System.Drawing.Color.Green);
        }

        private bool MatchesPattern(string key, string pattern)
        {
            // Support wildcards: * matches any characters
            // Convert pattern to regex
            string regexPattern = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
                .Replace("\\*", ".*") + "$";

            return System.Text.RegularExpressions.Regex.IsMatch(key, regexPattern,
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        private void BtnClearFilter_Click(object sender, EventArgs e)
        {
            txtFilter.Clear();
            ApplyFilter();
        }

        private void BtnCopyValue_Click(object sender, EventArgs e)
        {
            if (dgvConfigs.SelectedRows.Count == 0)
            {
                MessageBox.Show("Please select a row to copy its value.", "No Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            try
            {
                var selectedRow = dgvConfigs.SelectedRows[0];
                string value = "";

                if (_isKeyVaultMode)
                {
                    value = selectedRow.Cells["Value"].Value?.ToString() ?? "";
                }
                else if (_isRedisMode)
                {
                    value = selectedRow.Cells["Value"].Value?.ToString() ?? "";
                }
                else
                {
                    value = selectedRow.Cells["Value"].Value?.ToString() ?? "";
                }

                if (!string.IsNullOrEmpty(value))
                {
                    Clipboard.SetText(value);
                    UpdateStatus("Value copied to clipboard", System.Drawing.Color.Green);
                }
                else
                {
                    MessageBox.Show("The selected value is empty.", "Empty Value",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying value: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnCopyKey_Click(object sender, EventArgs e)
        {
            if (dgvConfigs.SelectedRows.Count == 0)
            {
                MessageBox.Show("Please select a row to copy its key.", "No Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            try
            {
                var selectedRow = dgvConfigs.SelectedRows[0];
                string key = "";

                // Key Vault uses "Name" column, others use "Key" column
                if (_isKeyVaultMode)
                {
                    key = selectedRow.Cells["Name"].Value?.ToString() ?? "";
                }
                else
                {
                    key = selectedRow.Cells["Key"].Value?.ToString() ?? "";
                }

                if (!string.IsNullOrEmpty(key))
                {
                    Clipboard.SetText(key);
                    UpdateStatus("Key copied to clipboard", System.Drawing.Color.Green);
                }
                else
                {
                    MessageBox.Show("The selected key is empty.", "Empty Key",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying key: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void BtnAdd_Click(object sender, EventArgs e)
        {
            if (_isKeyVaultMode)
            {
                await AddKeyVaultSecret();
            }
            else if (_isRedisMode)
            {
                await AddRedisKey();
            }
            else
            {
                await AddAzureAppConfig();
            }
        }

        private async Task AddAzureAppConfig()
        {
            if (_configClient == null) return;

            string key = txtKey.Text.Trim();
            string value = txtValue.Text.Trim();
            string label = txtLabel.Text.Trim();

            if (string.IsNullOrEmpty(key))
            {
                MessageBox.Show("Please enter a key.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                UpdateStatus("Adding configuration...", System.Drawing.Color.Blue);
                btnAdd.Enabled = false;

                var setting = new ConfigurationSetting(key, value);
                if (!string.IsNullOrEmpty(label))
                {
                    setting.Label = label;
                }

                await _configClient.SetConfigurationSettingAsync(setting);

                MessageBox.Show($"Configuration '{key}' added successfully!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtKey.Clear();
                txtValue.Clear();
                txtLabel.Clear();

                // Reload from Azure to update cache
                await LoadAzureAppConfigs();
            }
            catch (RequestFailedException ex)
            {
                MessageBox.Show($"Azure request failed: {ex.Message}\nStatus: {ex.Status}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to add configuration", System.Drawing.Color.Red);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error adding configuration: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to add configuration", System.Drawing.Color.Red);
            }
            finally
            {
                btnAdd.Enabled = true;
            }
        }

        private async Task AddRedisKey()
        {
            if (_redis == null || _redisDb == null) return;

            string key = txtKey.Text.Trim();
            string value = txtValue.Text.Trim();

            if (string.IsNullOrEmpty(key))
            {
                MessageBox.Show("Please enter a key.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                UpdateStatus("Adding Redis key...", System.Drawing.Color.Blue);
                btnAdd.Enabled = false;

                await _redisDb.StringSetAsync(key, value);

                MessageBox.Show($"Redis key '{key}' added successfully!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtKey.Clear();
                txtValue.Clear();

                // Reload from Redis to update cache
                await LoadRedisKeys();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error adding Redis key: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to add Redis key", System.Drawing.Color.Red);
            }
            finally
            {
                btnAdd.Enabled = true;
            }
        }

        private async Task AddKeyVaultSecret()
        {
            if (_keyVaultClient == null) return;

            string name = txtKey.Text.Trim();
            string value = txtValue.Text.Trim();

            if (string.IsNullOrEmpty(name))
            {
                MessageBox.Show("Please enter a secret name.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (string.IsNullOrEmpty(value))
            {
                MessageBox.Show("Please enter a secret value.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                UpdateStatus("Adding Key Vault secret...", System.Drawing.Color.Blue);
                btnAdd.Enabled = false;

                await _keyVaultClient.SetSecretAsync(name, value);

                MessageBox.Show($"Secret '{name}' added successfully to Key Vault!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtKey.Clear();
                txtValue.Clear();

                // Reload from Key Vault to update cache
                await LoadKeyVaultSecrets();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error adding Key Vault secret: {ex.Message}\n\n" +
                    "Make sure you have 'Set' permission on the Key Vault secrets.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to add Key Vault secret", System.Drawing.Color.Red);
            }
            finally
            {
                btnAdd.Enabled = true;
            }
        }

        private void BtnRefresh_Click(object sender, EventArgs e)
        {
            LoadConfigurations();
        }

        private void DgvConfigs_SelectionChanged(object sender, EventArgs e)
        {
            if (dgvConfigs.SelectedRows.Count > 0)
            {
                var selectedRow = dgvConfigs.SelectedRows[0];

                if (_isKeyVaultMode)
                {
                    txtKey.Text = selectedRow.Cells["Name"].Value?.ToString() ?? "";
                    txtValue.Text = selectedRow.Cells["Value"].Value?.ToString() ?? "";
                }
                else
                {
                    txtKey.Text = selectedRow.Cells["Key"].Value?.ToString() ?? "";
                    txtValue.Text = selectedRow.Cells["Value"].Value?.ToString() ?? "";

                    if (!_isRedisMode && selectedRow.Cells["Label"].Value != null)
                    {
                        txtLabel.Text = selectedRow.Cells["Label"].Value?.ToString() ?? "";
                    }
                }
            }
        }

        private async void BtnUpdate_Click(object sender, EventArgs e)
        {
            if (dgvConfigs.SelectedRows.Count == 0)
            {
                MessageBox.Show("Please select a row to update.", "No Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (_isKeyVaultMode)
            {
                await UpdateKeyVaultSecret();
            }
            else if (_isRedisMode)
            {
                await UpdateRedisKey();
            }
            else
            {
                await UpdateAzureAppConfig();
            }
        }

        private async Task UpdateAzureAppConfig()
        {
            if (_configClient == null) return;

            string key = txtKey.Text.Trim();
            string value = txtValue.Text.Trim();
            string label = txtLabel.Text.Trim();

            if (string.IsNullOrEmpty(key))
            {
                MessageBox.Show("Please enter a key.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                UpdateStatus("Updating configuration...", System.Drawing.Color.Blue);
                btnUpdate.Enabled = false;

                var setting = new ConfigurationSetting(key, value);
                if (!string.IsNullOrEmpty(label))
                {
                    setting.Label = label;
                }

                await _configClient.SetConfigurationSettingAsync(setting);

                MessageBox.Show($"Configuration '{key}' updated successfully!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                // Reload from Azure to update cache
                await LoadAzureAppConfigs();
            }
            catch (RequestFailedException ex)
            {
                MessageBox.Show($"Azure request failed: {ex.Message}\nStatus: {ex.Status}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to update configuration", System.Drawing.Color.Red);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error updating configuration: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to update configuration", System.Drawing.Color.Red);
            }
            finally
            {
                btnUpdate.Enabled = true;
            }
        }

        private async Task UpdateRedisKey()
        {
            if (_redis == null || _redisDb == null) return;

            string key = txtKey.Text.Trim();
            string value = txtValue.Text.Trim();

            if (string.IsNullOrEmpty(key))
            {
                MessageBox.Show("Please enter a key.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                UpdateStatus("Updating Redis key...", System.Drawing.Color.Blue);
                btnUpdate.Enabled = false;

                await _redisDb.StringSetAsync(key, value);

                MessageBox.Show($"Redis key '{key}' updated successfully!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                // Reload from Redis to update cache
                await LoadRedisKeys();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error updating Redis key: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to update Redis key", System.Drawing.Color.Red);
            }
            finally
            {
                btnUpdate.Enabled = true;
            }
        }

        private async Task UpdateKeyVaultSecret()
        {
            if (_keyVaultClient == null) return;

            string name = txtKey.Text.Trim();
            string value = txtValue.Text.Trim();

            if (string.IsNullOrEmpty(name))
            {
                MessageBox.Show("Please enter a secret name.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (string.IsNullOrEmpty(value))
            {
                MessageBox.Show("Please enter a secret value.", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                UpdateStatus("Updating Key Vault secret...", System.Drawing.Color.Blue);
                btnUpdate.Enabled = false;

                await _keyVaultClient.SetSecretAsync(name, value);

                MessageBox.Show($"Secret '{name}' updated successfully in Key Vault!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                // Reload from Key Vault to update cache
                await LoadKeyVaultSecrets();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error updating Key Vault secret: {ex.Message}\n\n" +
                    "Make sure you have 'Set' permission on the Key Vault secrets.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to update Key Vault secret", System.Drawing.Color.Red);
            }
            finally
            {
                btnUpdate.Enabled = true;
            }
        }

        private async void BtnDelete_Click(object sender, EventArgs e)
        {
            if (dgvConfigs.SelectedRows.Count == 0)
            {
                MessageBox.Show("Please select a row to delete.", "No Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var selectedRow = dgvConfigs.SelectedRows[0];
            string keyToDelete = "";

            if (_isKeyVaultMode)
            {
                keyToDelete = selectedRow.Cells["Name"].Value?.ToString() ?? "";
            }
            else
            {
                keyToDelete = selectedRow.Cells["Key"].Value?.ToString() ?? "";
            }

            if (string.IsNullOrEmpty(keyToDelete))
            {
                MessageBox.Show("Cannot delete: Key is empty.", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // Confirmation dialog
            string dataSourceName = _isKeyVaultMode ? "Key Vault secret" :
                                   _isRedisMode ? "Redis key" : "App Configuration";

            DialogResult result = MessageBox.Show(
                $"Are you sure you want to delete the following {dataSourceName}?\n\n" +
                $"Key: {keyToDelete}\n\n" +
                "This action cannot be undone.",
                "Confirm Delete",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (result == DialogResult.Yes)
            {
                if (_isKeyVaultMode)
                {
                    await DeleteKeyVaultSecret(keyToDelete);
                }
                else if (_isRedisMode)
                {
                    await DeleteRedisKey(keyToDelete);
                }
                else
                {
                    await DeleteAzureAppConfig(keyToDelete);
                }
            }
        }

        private async Task DeleteAzureAppConfig(string key)
        {
            if (_configClient == null) return;

            try
            {
                UpdateStatus($"Deleting configuration '{key}'...", System.Drawing.Color.Blue);
                btnDelete.Enabled = false;

                // Get label if exists for proper deletion
                string label = txtLabel.Text.Trim();

                if (!string.IsNullOrEmpty(label))
                {
                    await _configClient.DeleteConfigurationSettingAsync(key, label);
                }
                else
                {
                    await _configClient.DeleteConfigurationSettingAsync(key);
                }

                MessageBox.Show($"Configuration '{key}' deleted successfully!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtKey.Clear();
                txtValue.Clear();
                txtLabel.Clear();

                // Reload from Azure to update cache
                await LoadAzureAppConfigs();
            }
            catch (RequestFailedException ex)
            {
                MessageBox.Show($"Azure request failed: {ex.Message}\nStatus: {ex.Status}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to delete configuration", System.Drawing.Color.Red);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error deleting configuration: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to delete configuration", System.Drawing.Color.Red);
            }
            finally
            {
                btnDelete.Enabled = true;
            }
        }

        private async Task DeleteRedisKey(string key)
        {
            if (_redis == null || _redisDb == null) return;

            try
            {
                UpdateStatus($"Deleting Redis key '{key}'...", System.Drawing.Color.Blue);
                btnDelete.Enabled = false;

                await _redisDb.KeyDeleteAsync(key);

                MessageBox.Show($"Redis key '{key}' deleted successfully!", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtKey.Clear();
                txtValue.Clear();

                // Reload from Redis to update cache
                await LoadRedisKeys();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error deleting Redis key: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to delete Redis key", System.Drawing.Color.Red);
            }
            finally
            {
                btnDelete.Enabled = true;
            }
        }

        private async Task DeleteKeyVaultSecret(string name)
        {
            if (_keyVaultClient == null) return;

            try
            {
                UpdateStatus($"Deleting Key Vault secret '{name}'...", System.Drawing.Color.Blue);
                btnDelete.Enabled = false;

                // Start the delete operation
                var operation = await _keyVaultClient.StartDeleteSecretAsync(name);

                // Wait for the delete to complete
                await operation.WaitForCompletionAsync();

                MessageBox.Show($"Secret '{name}' deleted successfully from Key Vault!\n\n" +
                    "Note: The secret is soft-deleted and can be recovered or purged.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);

                txtKey.Clear();
                txtValue.Clear();

                // Reload from Key Vault to update cache
                await LoadKeyVaultSecrets();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error deleting Key Vault secret: {ex.Message}\n\n" +
                    "Make sure you have 'Delete' permission on the Key Vault secrets.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Failed to delete Key Vault secret", System.Drawing.Color.Red);
            }
            finally
            {
                btnDelete.Enabled = true;
            }
        }

        private void UpdateStatus(string message, System.Drawing.Color color)
        {
            lblStatus.Text = message;
            lblStatus.ForeColor = color;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _redis?.Dispose();
            }
            base.Dispose(disposing);
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    public class ConfigItem
    {
        public string Key { get; set; }
        public string Value { get; set; }
        public string Label { get; set; }
        public string ContentType { get; set; }
        public DateTime LastModified { get; set; }
    }

    public class RedisItem
    {
        public string Key { get; set; }
        public string Value { get; set; }
        public string Type { get; set; }
        public string TTL { get; set; }
    }

    public class KeyVaultItem
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string ContentType { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedOn { get; set; }
        public DateTime UpdatedOn { get; set; }
    }
}