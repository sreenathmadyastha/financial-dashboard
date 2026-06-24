const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const indexHtml = fs.readFileSync(
  path.join(__dirname, 'public', 'index.html'), 'utf-8'
);

app.get('*', (req, res) => {
  const nonce = crypto.randomBytes(16).toString('base64');

  // Inject nonce into every <script> tag
  const html = indexHtml.replace(
    /<script/g,
    `<script nonce="${nonce}"`
  );

  res.setHeader(
    'Content-Security-Policy',
    `script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
    `object-src 'none'; ` +
    `base-uri 'self'; ` +
    `default-src 'self'; ` +
    `style-src 'self' 'unsafe-inline'; ` +
    `connect-src 'self' https://your-api-domain.com; ` +
    `img-src 'self' data:;`
  );

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// Why this works with strict-dynamic: The nonce trusts the initial script tag. strict-dynamic 
// then propagates that trust to any scripts those scripts load dynamically — which is exactly 
// how Vite's module graph works (import(), dynamic chunks, etc.). 'unsafe-inline' is dropped entirely.