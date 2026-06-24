Perfect. Now I can see exactly where to hook in. The key lines are:

Line 159: const content = await fs.promises.readFile(safeFilePath)
Line 160–163: Content-Type check and headers — text/html path already exists
Line 164–165: res.writeHead(200, headers) then res.end(content, 'utf-8')

The nonce injection goes right in the text/html branch. Here's the exact change:

In createServer — generate nonce per request (add near line 183 where headers are set)
jsconst nonce = require('crypto').randomBytes(16).toString('base64');

Replace lines 160–165 with this
jsconst isHtml = contentType === 'text/html';

let responseContent = content;

if (isHtml) {
// Inject nonce into all <script> tags for strict-dynamic CSP
responseContent = content
.toString('utf-8')
.replace(/<script/g, `<script nonce="${nonce}"`);
}

const headers = isHtml
? { 'Content-Type': contentType, ...NO_CACHE_HEADERS }
: { 'Content-Type': contentType };

res.writeHead(200, headers);
res.end(responseContent, 'utf-8');

Update your CSP script-src line (line 201 from previous image)
js`script-src 'nonce-${nonce}' 'strict-dynamic' https://js-cdn.dynatrace.com; ` +
Remove 'unsafe-inline' entirely — 'strict-dynamic' with a nonce replaces it.

Why this works cleanly with your existing structure

handleRequest is already async — no changes needed there
The text/html branch is already separate (line 161) — you're just augmenting it
nonce is generated once per request in createServer's request handler scope, so it's consistent between the CSP header and the HTML rewrite
Vite's built output has <script type="module" src="..."> tags — the regex /<script/g catches all of them correctly
serveIndex (line 155) also calls into this same path, so SPA fallback routes get the nonce too

Also update serveIndex if it independently writes HTML
Looking at line 110–123, serveIndex likely calls handleRequest internally or writes index.html directly. If it does its own res.end, pass nonce into it:
jsasync function serveIndex(res, context, nonce) { ... }
And call it as:
jsawait serveIndex(res, context, nonce);
Share lines 110–123 of serveIndex if you want me to confirm that part.

Now I can see the full picture. serveIndex (lines 110–124) is a separate code path that independently writes index.html — it does its own readFile and res.writeHead/res.end on lines 115–116. So nonce injection must happen in both places.
Here are the exact changes:

1. serveIndex — lines 115–116
   Current:
   js
   const indexContent = await fs.promises.readFile(safeIndexPath);
   res.writeHead(200, { 'Content-Type': 'text/html', ...NO_CACHE_HEADERS });
   res.end(indexContent, 'utf-8');
   Replace with:
   js
   const indexContent = await fs.promises.readFile(safeIndexPath, 'utf-8');
   const noncedHtml = indexContent.replace(/<script/g, `<script nonce="${nonce}"`);
   res.writeHead(200, { 'Content-Type': 'text/html', ...NO_CACHE_HEADERS });
   res.end(noncedHtml, 'utf-8');

2. Update serveIndex signature to accept nonce
   Line 110 — current:
   jsasync function serveIndex(res, context) {
   Change to:
   jsasync function serveIndex(res, context, nonce) {

3. Both call sites pass nonce in — lines 155 and 167
   js// line 155
   await serveIndex(res, context, nonce);

// line 167 (ENOENT fallback in handleRequest)
await serveIndex(res, context, nonce);

4. handleRequest — nonce must come from the outer request scope
   Since handleRequest receives (req, res, context), nonce needs to be generated one level up in createServer's request handler and passed in:
   createServer request handler (line 183 area):
   jsconst nonce = require('crypto').randomBytes(16).toString('base64');

// Set CSP header using this nonce
res.setHeader(
'Content-Security-Policy',
`default-src 'self'; ` +
`script-src 'nonce-${nonce}' 'strict-dynamic' https://js-cdn.dynatrace.com; ` +
// ... rest of your directives
);

handleRequest(req, res, context, nonce).catch((err) => {
sendServerError(res, err.code);
});
Update handleRequest signature:
jsasync function handleRequest(req, res, context, nonce) {

Full call chain summary
createServer request handler
→ generates nonce
→ sets CSP header with nonce-${nonce}
  → calls handleRequest(req, res, context, nonce)
      → calls serveIndex(res, context, nonce)   [line 155]
      → or serveIndex(res, context, nonce)       [line 167 ENOENT fallback]
          → rewrites <script → <script nonce="${nonce}"
→ res.end(noncedHtml)
→ for non-HTML assets: serves as-is (no nonce needed)
This is a clean minimal change — no restructuring needed, just threading nonce through the existing call chain.
