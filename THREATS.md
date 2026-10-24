# Threat Model & Security Mitigations (TrustVault)

### 1. Insecure Direct Object References (IDOR)
- **Threat:** Attacker modifies document UUID in API calls to access unauthorized documents.
- **Mitigation:** Server performs a live query on every single request checking active grants in the database before serving bytes.
- **Result:** Denied with 403 Forbidden and logged as `ACCESS_DENIED`.

### 2. Stale Permissions & Browser Cache Poisoning
- **Threat:** User downloads a file, owner revokes access, but user downloads again from browser memory cache.
- **Mitigation:** Strict `Cache-Control: no-store, no-cache, must-revalidate` headers sent on backend and `cache: "no-store"` enforced on frontend fetch.

### 3. Path Traversal & Malicious Filenames
- **Threat:** Malicious file uploads containing directory traversal paths (e.g. `../../etc/passwd`).
- **Mitigation:** Files are never saved with user-provided names. Random cryptographic UUIDs are generated for disk storage outside public web directories.

### 4. Tamper-Evident Audit Logging
- **Threat:** Database administrator or compromised user modifies audit records.
- **Mitigation:** Append-only SHA-256 hash chaining where each event hash depends on the previous record's hash (`event_hash = SHA256(data + previous_hash)`).
