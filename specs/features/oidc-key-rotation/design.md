# Design: Rotacao de Chaves OIDC

## Status

- Status: draft
- Created: 2026-05-06
- Updated: 2026-05-06

## Current Behavior

`satoidc/satoidc/auth/oauth2.py` gera uma chave RSA em memoria no import da aplicacao. `satoidc/satoidc/routes/oauth2.py` publica o JWKS a partir dessa chave em memoria.

Impactos:

- Restart invalida a chave publica anterior.
- Replicas podem assinar tokens com chaves diferentes.
- Nao ha ciclo de vida de chaves, auditoria, nem garantia de `kid` estavel.

## Target Components

- `OidcSigningKey` model: representa metadados, estado, JWK publico e referencia ao backend criptografico.
- `OidcSigningKeyRepository`: consulta e transiciona estados de chaves com transacao.
- `OidcSigningService`: assina JWTs usando a chave `active` e registra `token.signed`.
- `OidcKeyRotationService`: gera, ativa, rebaixa e aposenta chaves.
- `OidcAuditLog` ou integracao com mecanismo de auditoria existente: registra eventos criticos.
- Rotas publicas de discovery/JWKS e rotas administrativas sob `/admin/oidc/keys`.

## Backend Cryptografico

### Preferencial: Vault Transit

O banco armazena:

- `public_jwk`
- `vault_key_name`
- `vault_key_version`
- metadados de lifecycle

A assinatura e feita via Vault Transit. A chave privada nao passa pela aplicacao.

### MVP: banco com chave privada criptografada

O banco armazena `private_jwk_encrypted`, nunca `private_jwk` em texto puro.

Pre-condicoes:

- A chave de criptografia de dados nao deve ficar no mesmo registro.
- Logs e erros devem mascarar qualquer material privado.
- O material descriptografado deve existir apenas no escopo minimo necessario para assinatura.

## State Transitions

```text
created -> validating
validating -> active
active -> validating
validating -> retired
```

Regras:

- So pode existir uma chave `active`.
- Ativacao deve ocorrer em transacao unica.
- Ao ativar uma nova chave, a chave ativa anterior recebe `status=validating`, `validating_since=now` e `retired_after`.
- Chave `retired` nao pode voltar a `active` sem decisao explicita futura.

## Token Signing

O emissor de tokens deve resolver a chave `active` no momento da assinatura, sem depender de restart.

Header minimo:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "<active-kid>"
}
```

Falhas ao obter a chave ativa ou assinar devem ser logadas sem material sensivel e retornar erro apropriado ao fluxo OAuth/OIDC.

## JWKS

`/.well-known/jwks.json` retorna somente chaves em `active` ou `validating`.

Cada chave publicada deve conter apenas parametros publicos, por exemplo:

- `kid`
- `alg`
- `kty`
- `use`
- parametros publicos RSA como `n` e `e`

`private_jwk_encrypted`, referencias internas e campos administrativos nao devem sair no JWKS.

## Retirement Window

`retired_after` deve considerar:

- maior TTL de token assinado por chave OIDC;
- TTL/cache efetivo do JWKS;
- margem operacional extra.

Configuracao inicial sugerida:

```text
retired_after = rotated_at + max_token_ttl + jwks_cache_ttl + extra_margin
```

## Administrative Security

Endpoints administrativos devem exigir autorizacao administrativa/root existente no SatOIDC.

Operacoes manuais devem registrar `actor` quando houver usuario autenticado. Jobs devem registrar `actor=system`.

## Compatibility Notes

O contrato alvo usa `/.well-known/openid-configuration` e `/.well-known/jwks.json`. Os endpoints OAuth continuam sob `/oauth`, mas discovery e JWKS nao devem depender do prefixo `/oauth`.
