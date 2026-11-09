# AI Usage & Prompt Log

## Entry 1: 2026-11-03
- **Prompt:** Build Flask backend with strict authorization and RBAC.
- **AI Output:** Basic route handling with standard logins.
- **Issues Found:** Initial code lacked strict check for user permission verification.
- **Fix:** Added strict backend authorization check logic before file streaming in `/download/<doc_id>`.