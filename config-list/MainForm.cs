using System;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Azure;
using Azure.Data.AppConfiguration;
using StackExchange.Redis;

namespace AzureAppConfigManager
{
    public partial class MainForm : Form
    {
        private ConfigurationClient _configClient;
        private ConnectionMultiplexer _redis;
        private IDatabase _redisDb;

        private MenuStrip menuStrip;
        private DataGridView dgvConfigs;
        private TextBox txtKey;
        private TextBox txtValue;
        private TextBox txtLabel;
        private Button btnAdd;
        private Button btnRefresh;
        private Label lblStatus;
        private Panel pnlAddConfig;

        private bool _isRedisMode = false;

        public MainForm()
        {
            InitializeComponent();
            InitializeAzureClient();
            LoadConfigurations();
        }

        private void InitializeComponent()
        {
            this.Text = "Azure App Configuration Manager";
            this.Size = new System.Drawing.Size(900, 630);
            this.StartPosition = FormStartPosition.CenterScreen;

            // Menu Strip
            menuStrip = new MenuStrip();

            ToolStripMenuItem dataSourceMenu = new ToolStripMenuItem("Data Source");
            ToolStripMenuItem appConfigMenu = new ToolStripMenuItem("Azure App Configuration");
            ToolStripMenuItem redisMenu = new ToolStripMenuItem("Redis Cache");

            appConfigMenu.Click += AppConfigMenu_Click;
            redisMenu.Click += RedisMenu_Click;

            dataSourceMenu.DropDownItems.Add(appConfigMenu);
            dataSourceMenu.DropDownItems.Add(redisMenu);
            menuStrip.Items.Add(dataSourceMenu);

            this.MainMenuStrip = menuStrip;
            this.Controls.Add(menuStrip);

            // DataGridView for listing configurations
            dgvConfigs = new DataGridView
            {
                Location = new System.Drawing.Point(20, 50),
                Size = new System.Drawing.Size(840, 350),
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                ReadOnly = true,
                AllowUserToAddRows = false
            };
            this.Controls.Add(dgvConfigs);

            // Refresh button
            btnRefresh = new Button
            {
                Text = "Refresh",
                Location = new System.Drawing.Point(760, 410),
                Size = new System.Drawing.Size(100, 30)
            };
            btnRefresh.Click += BtnRefresh_Click;
            this.Controls.Add(btnRefresh);

            // Panel for Add Configuration section
            pnlAddConfig = new Panel
            {
                Location = new System.Drawing.Point(20, 450),
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
                Location = new System.Drawing.Point(20, 555),
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

        private void AppConfigMenu_Click(object sender, EventArgs e)
        {
            _isRedisMode = false;
            this.Text = "Azure App Configuration Manager";
            txtLabel.Visible = true;
            pnlAddConfig.Controls.OfType<Label>().FirstOrDefault(l => l.Text == "Label:")?.Show();

            if (_configClient == null)
                InitializeAzureClient();

            LoadConfigurations();
        }

        private void RedisMenu_Click(object sender, EventArgs e)
        {
            _isRedisMode = true;
            this.Text = "Redis Cache Manager";
            txtLabel.Visible = false;
            pnlAddConfig.Controls.OfType<Label>().FirstOrDefault(l => l.Text == "Label:")?.Hide();

            if (_redis == null)
                InitializeRedisClient();

            LoadConfigurations();
        }

        private async void LoadConfigurations()
        {
            if (_isRedisMode)
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
                UpdateStatus("Loading configurations...", System.Drawing.Color.Blue);
                btnRefresh.Enabled = false;

                var configs = new System.Collections.Generic.List<ConfigItem>();

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

                dgvConfigs.DataSource = configs.OrderBy(c => c.Key).ToList();
                UpdateStatus($"Loaded {configs.Count} configuration(s)", System.Drawing.Color.Green);
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

                var redisItems = new System.Collections.Generic.List<RedisItem>();

                await Task.Run(() =>
                {
                    var endpoints = _redis.GetEndPoints();
                    var server = _redis.GetServer(endpoints[0]);
                    var keys = server.Keys(pattern: "*");

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
                    }
                });

                dgvConfigs.DataSource = redisItems.OrderBy(r => r.Key).ToList();
                UpdateStatus($"Loaded {redisItems.Count} Redis key(s)", System.Drawing.Color.Green);
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

        private async void BtnAdd_Click(object sender, EventArgs e)
        {
            if (_isRedisMode)
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

        private void BtnRefresh_Click(object sender, EventArgs e)
        {
            LoadConfigurations();
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
}