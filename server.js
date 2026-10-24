// Minimal static file server with HTTP Basic Auth in front of it.
// No framework, no dependencies - just Node's own http module - so there is
// nothing extra to install or keep patched for a single-file, single-route site.
//
// The id and password are never in this file or in the repo: they are read
// from the AUTH_USER / AUTH_PASS environment variables, set in the Render
// dashboard (Settings -> Environment). Anyone without them gets the browser's
// own native login prompt and nothing else - not even the page's own HTML.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 10000;
const REALM = 'Reconciliation Studio';
const PAGE_PATH = path.join(__dirname, 'index.html');

const page = fs.readFileSync(PAGE_PATH); // read once at startup, served from memory after that

function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // crypto.timingSafeEqual throws if the lengths differ, so pad to a common
  // length first - this still compares in constant time for equal inputs,
  // which is the case that actually matters against a timing attack.
  const len = Math.max(bufA.length, bufB.length, 1);
  const padA = Buffer.alloc(len), padB = Buffer.alloc(len);
  bufA.copy(padA); bufB.copy(padB);
  return crypto.timingSafeEqual(padA, padB) && bufA.length === bufB.length;
}

function isAuthorized(req) {
  const user = process.env.AUTH_USER, pass = process.env.AUTH_PASS;
  if (!user || !pass) return false; // fail closed: misconfigured means no access, not open access
  const header = req.headers['authorization'] || '';
  const match = /^Basic\s+(.+)$/.exec(header);
  if (!match) return false;
  let decoded;
  try { decoded = Buffer.from(match[1], 'base64').toString('utf8'); } catch (e) { return false; }
  const sep = decoded.indexOf(':');
  if (sep < 0) return false;
  const gotUser = decoded.slice(0, sep), gotPass = decoded.slice(sep + 1);
  return timingSafeEqual(gotUser, user) && timingSafeEqual(gotPass, pass);
}

function askForAuth(res) {
  res.writeHead(401, {
    'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
    'Content-Type': 'text/plain; charset=utf-8',
  });
  res.end('A valid id and password is needed to open this page.');
}

const server = http.createServer((req, res) => {
  if (!isAuthorized(req)) { askForAuth(res); return; }
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': page.length,
    'Cache-Control': 'no-store',
  });
  res.end(page);
});

server.listen(PORT, () => {
  if (!process.env.AUTH_USER || !process.env.AUTH_PASS) {
    console.warn('AUTH_USER / AUTH_PASS are not set - every request will be refused until they are.');
  }
  console.log(`Listening on port ${PORT}`);
});
