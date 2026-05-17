# Local Development Troubleshooting

Updated: 2026-05-17

This page tracks local-only failure modes that can block development setup.
It is not a substitute for production database backup and migration procedures.

## Alembic Cannot Locate A Revision

Symptom:

```text
FAILED: Can't locate revision identified by '7b0c2a4d9f31'
```

Cause:

- The local SQLite database has an `alembic_version` value that does not exist
  under `satoidc/migrations/versions/`.
- This usually comes from a local migration that was generated during earlier
  work but was not committed, or from a database file copied from another local
  branch.

Safe local repair workflow:

1. Do not delete the SQLite file if it contains users or clients you still need.
2. Inspect the available migration files:

   ```powershell
   cd satoidc
   Get-ChildItem .\migrations\versions
   ```

3. Inspect the local database schema before stamping or editing the version row.
   For SQLite, compare the existing tables and columns with the migrations that
   are present in the repository.
4. Back up the local database:

   ```powershell
   Copy-Item .\satoidc.db .\satoidc.db.before-alembic-repair
   ```

5. For the known 2026-05-17 local case, `satoidc.db` pointed at missing revision
   `7b0c2a4d9f31`. The schema already included the migrations through
   `7f362123846e` but did not include `77c82d7f11f8`, so the safe local repair
   was to update `alembic_version` to `7f362123846e` and then run:

   ```powershell
   poetry run alembic upgrade head
   ```

6. Validate the result:

   ```powershell
   poetry run alembic current
   ```

Expected current head after the 2026-05-17 repair:

```text
77c82d7f11f8 (head)
```

Important constraints:

- Do not apply this known-case repair to another database without checking the
  schema first.
- Do not hand-write new migrations to fix local version drift. New schema
  migrations must be generated with:

  ```powershell
  poetry run alembic revision --autogenerate -m "<message>"
  ```

  Then edit only the minimum necessary dialect-specific or data-migration
  details.
- Treat `satoidc.db` and `database.db` as local runtime data. They are not source
  files and should not be committed.
