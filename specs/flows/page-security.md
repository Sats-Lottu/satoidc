# Page Security Flow

Status: draft
Updated: 2026-05-08

## Protected NiceGUI Pages

1. A NiceGUI page is decorated with `page_security()`.
2. The decorator reads the current request from NiceGUI context.
3. If `request.session["user_id"]` is missing, the user is redirected to `/login`.
4. If `user_id` is not a valid UUID, the user is redirected to `/login`.
5. The server loads active, non-disabled permissions for the user.
6. Expired permissions are ignored.
7. `root` authorizes every protected page.
8. For non-root users, `mode="all"` requires every requested permission and `mode="any"` requires at least one requested permission.
9. If authorization fails, the user is redirected to `/forbidden`.
10. If authorization succeeds, the protected page function runs and its return value is preserved.

## Notes

- The decorator should remain thin and delegate testable authorization behavior to helper functions.
- Permission values may arrive as `PermissionsEnum` members or strings; authorization normalizes both to strings before comparison.
- Permission taxonomy remains unresolved: current UI references `developer`, while `PermissionsEnum` only defines `root`, `admin`, and `support`.
