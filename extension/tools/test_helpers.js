"use strict";

const assert = require("node:assert/strict");
const H = require("../helpers.js");

assert.equal(H.isAllowlisted("https://accounts.google.com/signin"), true);
assert.equal(H.isAllowlisted("https://evil-google.com/signin"), false);
assert.equal(H.isAllowlisted("https://news.wikipedia.org/wiki/Test"), true);
assert.equal(H.isAllowlisted("https://sbi-kyc-update.xyz/login"), false);
assert.equal(H.registeredDomain("mail.example.co.in"), "example.co.in");
assert.equal(H.registeredDomain("shop.example.com"), "example.com");
assert.equal(H.cacheKey("HTTPS://Example.COM:443/a//b?q=one#two"), "example.com/a/b");
assert.equal(H.cacheKey("http://example.com:8080/"), "example.com:8080/");
assert.equal(
  H.stripReasonMarkup("`RULE_12` **Urgent** [payment](https://example.test) <b>request</b>"),
  "RULE_12 Urgent payment request"
);
assert.equal(H.shouldSkipUrl("http://localhost:3000/test", H.DEFAULT_API_BASE), true);
assert.equal(H.shouldSkipUrl(`${H.DEFAULT_API_BASE}/api/health`, H.DEFAULT_API_BASE), true);
assert.equal(H.shouldSkipUrl("https://unfamiliar-example.test/path", H.DEFAULT_API_BASE), false);

console.log(`helpers: ${H.ALLOWLIST.length} allowlisted domains; all assertions passed`);
