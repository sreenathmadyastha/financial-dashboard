const { AppConfigurationClient } = require('@azure/app-configuration');
const { DefaultAzureCredential } = require('@azure/identity');

async function main() {
  const endpoint = process.env.APP_CONFIG_ENDPOINT; // e.g. https://your-appconfig.azconfig.io
  const client = new AppConfigurationClient(endpoint, new DefaultAzureCredential());

  const setting = await client.getConfigurationSetting({
    key: 'CSP:FrameAncestors',
    label: process.env.APP_CONFIG_LABEL || undefined,
  });

  // print raw value to stdout so shell can capture it
  process.stdout.write(setting.value);
}

main().catch((err) => {
  console.error('Failed to fetch CSP config:', err.message);
  process.exit(1);
});