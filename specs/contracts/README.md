# Contracts

Use this folder for contracts that must stay stable across features.

Good candidates in SatOIDC:

- OAuth2 and OIDC endpoints.
- ID token and JWKS shape.
- UserInfo response.
- LNURL-auth callback parameters.
- Database model expectations.
- Client metadata shape.

Contracts should be precise enough to generate or validate tests from them.
