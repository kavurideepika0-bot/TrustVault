# Security Threat Model & Mitigations

## 1. Direct URL/API Access Bypass
- **Threat:** User tries to download file directly using `/download/<id>` link without permission.
- **Mitigation:** Backend validates session user ID against permissions table in DB for every request.

## 2. Dynamic Access Revocation
- **Threat:** User uses cached session after permissions are revoked.
- **Mitigation:** Permissions are checked dynamically per request; access stops immediately upon revocation.