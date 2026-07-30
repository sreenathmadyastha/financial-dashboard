const frameAncestors = process.env.CSP_FRAME_ANCESTORS || "'self'";

app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64'); // your existing nonce logic
  res.locals.nonce = nonce;

  res.setHeader(
    'Content-Security-Policy',
    [
      `default-src 'self'`,
      `script-src 'self' 'nonce-${nonce}'`,
      `frame-ancestors 'self' ${frameAncestors}`,
      // ...rest of your existing directives
    ].join('; ')
  );
  next();
});