# Changelog

## 1.1.0 (2026-10-21)

- Requires `firebase/php-jwt` **^7.0**. Composer blocks all 6.x releases because of CVE-2025-45769 (GHSA-2x45-7fc3-mxwq).
- First standalone repository, split from the Identvia monorepo with its history. Added `.gitignore` and GitHub Actions CI (PHP 8.1–8.4).
- Includes the 1.1 delegation helpers: `tokenExchange` (RFC 8693), CIBA and `authorization_details` (RFC 9396). These require server 2026-10-21_5+.

