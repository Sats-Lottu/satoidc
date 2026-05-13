# Spec: Rotacao de Chaves OIDC no SatOIDC

## Status

- Status: implemented
- Owner: TBD
- Created: 2026-05-06
- Updated: 2026-05-13
- Related code:
  - `satoidc/satoidc/auth/oauth2.py`
  - `satoidc/satoidc/routes/oauth2.py`
  - `satoidc/satoidc/models/`
  - `satoidc/migrations/`
- Related specs:
  - [OIDC Contract](../../contracts/oidc.md)
  - [Design](design.md)
  - [API Contract](api-contract.md)
  - [Test Plan](test-plan.md)
  - [Tasks](tasks.md)

## Intent

Implementar um mecanismo seguro de geracao, ativacao, rotacao, publicacao e aposentadoria de chaves de assinatura OIDC, garantindo que tokens JWT emitidos pelo SatOIDC possam ser validados corretamente pelos clientes por meio do endpoint publico JWKS.

A regra principal e: nunca remover uma chave publica do JWKS enquanto ainda puder existir token valido assinado por ela.

## Context

O SatOIDC atualmente assina tokens OIDC com uma chave RSA gerada em memoria durante a inicializacao da aplicacao. Esse comportamento torna tokens antigos potencialmente invalidos apos restart e impossibilita operacao consistente com multiplas replicas.

A feature deve substituir esse comportamento por um ciclo de vida persistente de chaves, com publicacao controlada no JWKS, uso obrigatorio de `kid` nos JWTs e trilha de auditoria para operacoes criticas.

## Scope

In scope:

- Geracao de novas chaves assimetricas para assinatura OIDC.
- Definicao de uma unica chave ativa para assinatura.
- Publicacao de chaves publicas em estado `active` e `validating` no JWKS.
- Inclusao de `kid` no header de todo JWT emitido.
- Manutencao temporaria de chaves antigas enquanto tokens assinados por elas ainda puderem ser validos.
- Remocao segura de chaves expiradas do JWKS.
- Auditoria de eventos de criacao, ativacao, rebaixamento, aposentadoria e assinatura.
- Publicacao de `jwks_uri` no documento de descoberta OIDC.

Out of scope:

- Rotacao automatica de client secrets.
- Rotacao de refresh tokens.
- Integracao obrigatoria com HSM fisico.

## Architectural Decision

A solucao preferencial deve usar Vault Transit como backend criptografico.

O MVP implementado armazena a chave privada no banco criptografada com uma chave derivada de `OAUTH2_JWT_SECRET_KEY`; ela nunca e exposta por endpoints, logs, documentos de descoberta ou eventos de auditoria.

A aplicacao SatOIDC nao deve expor a chave privada. Ela deve apenas solicitar assinatura ao backend criptografico ou carregar a chave privada criptografada em ambiente controlado no MVP.

## Key States

Cada chave de assinatura deve possuir exatamente um estado:

- `active`: chave usada para assinar novos tokens.
- `validating`: chave antiga, ainda publicada no JWKS para validar tokens ja emitidos.
- `retired`: chave removida do JWKS e nao usada para assinatura.

Em qualquer momento deve existir no maximo uma chave `active`. Em operacao normal deve existir exatamente uma chave `active` antes de emitir tokens.

## Functional Requirements

### RF01 - Gerar nova chave de assinatura

O sistema deve permitir gerar uma nova chave assimetrica para assinatura de tokens OIDC.

A chave deve conter:

- `kid`
- `alg`
- `kty`
- `use`
- `created_at`
- `status`
- `public_jwk`
- `backend_reference`

Exemplo:

```json
{
  "kid": "sat-oidc-2026-05-06-001",
  "alg": "RS256",
  "kty": "RSA",
  "use": "sig",
  "status": "validating"
}
```

### RF02 - Ativar nova chave

O sistema deve permitir tornar uma chave ociosa ou recem-criada em chave ativa.

Ao ativar uma nova chave:

- A chave anterior `active` deve mudar para `validating`.
- A nova chave deve mudar para `active`.
- Novos tokens devem ser assinados com a nova `kid`.
- Ambas as chaves devem aparecer no JWKS enquanto a chave antiga estiver em janela de validacao.

### RF03 - Assinar tokens com kid

Todo JWT emitido pelo SatOIDC deve conter no header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sat-oidc-2026-05-06-001"
}
```

O valor de `kid` deve corresponder a uma chave publicada no JWKS enquanto o token estiver valido.

### RF04 - Publicar JWKS

O SatOIDC deve expor:

```http
GET /.well-known/jwks.json
```

O endpoint deve retornar todas as chaves publicas com estado `active` ou `validating`.

O endpoint nao deve retornar chaves `retired` nem qualquer material privado.

### RF05 - Aposentar chave antiga

O sistema deve aposentar uma chave quando:

```text
now > retired_after
```

Onde:

```text
retired_after = momento_da_rotacao + maior_TTL_de_token + margem_de_cache_JWKS
```

Exemplo:

```text
access_token_ttl = 15 minutos
id_token_ttl = 15 minutos
jwks_cache_ttl = 15 minutos
margem_extra = 15 minutos

retired_after = rotacao + 45 minutos
```

### RF06 - Auditoria

Toda operacao de rotacao deve gerar evento de auditoria.

Eventos minimos:

- `key.created`
- `key.activated`
- `key.demoted_to_validating`
- `key.retired`
- `token.signed`

Evento minimo:

```json
{
  "event": "key.activated",
  "kid": "sat-oidc-2026-05-06-001",
  "actor": "system",
  "occurred_at": "2026-05-06T10:30:00Z"
}
```

## Non-Functional Requirements

### RNF01 - Seguranca

A chave privada nao deve ser armazenada em texto puro e nunca deve aparecer no JWKS, logs, respostas HTTP, eventos de auditoria ou mensagens de erro.

### RNF02 - Compatibilidade OIDC

O provedor deve publicar `jwks_uri` no documento de descoberta:

```http
GET /.well-known/openid-configuration
```

Exemplo:

```json
{
  "issuer": "https://auth.exemplo.com",
  "jwks_uri": "https://auth.exemplo.com/.well-known/jwks.json"
}
```

### RNF03 - Disponibilidade

A rotacao de chave nao deve invalidar tokens ainda validos.

### RNF04 - Observabilidade

O sistema deve registrar:

- `kid` usado em cada assinatura.
- Falhas de assinatura.
- Falhas de leitura do backend criptografico.
- Mudancas de estado das chaves.

## Data Model

Para MVP com banco:

```text
oidc_signing_keys
- id
- kid
- alg
- kty
- use
- status
- public_jwk
- private_jwk_encrypted
- backend_reference
- created_at
- activated_at
- validating_since
- retired_at
- retired_after
```

Com Vault Transit:

```text
oidc_signing_keys
- id
- kid
- alg
- kty
- use
- status
- public_jwk
- vault_key_name
- vault_key_version
- created_at
- activated_at
- validating_since
- retired_at
- retired_after
```

## Rotation Flow

1. Administrador ou job automatico solicita rotacao.
2. Sistema cria nova chave no backend criptografico.
3. Sistema obtem ou registra a chave publica correspondente.
4. Nova chave e publicada no JWKS como `validating`.
5. Sistema ativa nova chave.
6. Chave anterior muda para `validating`.
7. Novos tokens passam a usar a nova `kid`.
8. Apos a janela de seguranca, chave antiga muda para `retired`.
9. Chave `retired` deixa de aparecer no JWKS.

## Use Cases

### UC01 - Emitir token

Dado que existe uma chave `active`, quando o SatOIDC emitir um ID Token, entao o token deve ser assinado com a chave `active` e o header JWT deve conter o `kid` correto.

### UC02 - Rotacionar chave

Dado que existe uma chave `active`, quando uma nova chave for ativada, entao a chave antiga deve mudar para `validating`, a nova chave deve mudar para `active` e ambas devem aparecer no JWKS.

### UC03 - Aposentar chave

Dado que uma chave `validating` ultrapassou `retired_after`, quando o job de limpeza executar, entao a chave deve mudar para `retired` e deve ser removida do JWKS.

## Acceptance Criteria

- CA01: Tokens emitidos antes da rotacao continuam validos ate expirarem.
- CA02: Tokens emitidos depois da rotacao usam a nova `kid`.
- CA03: O JWKS publica a chave ativa e as chaves antigas ainda validas.
- CA04: Nenhuma chave privada aparece no JWKS.
- CA05: Chaves `retired` nao aparecem no JWKS.
- CA06: Toda rotacao gera evento de auditoria.
- CA07: A aplicacao nao precisa ser reiniciada para usar a nova chave ativa.

## Expected Tests

Unit:

- Deve selecionar apenas uma chave `active`.
- Deve gerar `kid` unico.
- Deve impedir duas chaves `active` ao mesmo tempo.
- Deve mover chave antiga para `validating`.
- Deve ocultar `retired` do JWKS.

Integration:

- Emitir token antes da rotacao.
- Rotacionar chave.
- Validar token antigo usando JWKS.
- Emitir token novo.
- Validar token novo usando JWKS.
- Aposentar chave antiga.
- Verificar que token antigo expirado nao depende mais da chave removida.

Security:

- Garantir que `private_jwk` nao aparece em logs.
- Garantir que `private_jwk` nao aparece no endpoint JWKS.
- Garantir que apenas usuario/admin autorizado aciona rotacao manual.
- Garantir auditoria de todas as operacoes criticas.

## Example Rotation Policy

```text
Algoritmo: RS256
Rotacao automatica: mensal
Access token TTL: 15 minutos
ID token TTL: 15 minutos
JWKS Cache-Control: 300 segundos
Retencao de chave antiga no JWKS: 1 hora
Refresh token: opaco, rotacionado separadamente no banco
```

## Minimal Administrative Interface

Internal endpoints:

```http
POST /admin/oidc/keys
POST /admin/oidc/keys/{kid}/activate
POST /admin/oidc/keys/rotate
POST /admin/oidc/keys/retire-expired
GET  /admin/oidc/keys
```

Public endpoints:

```http
GET /.well-known/openid-configuration
GET /.well-known/jwks.json
```

Discovery and JWKS should use the root well-known endpoints above. OAuth protocol endpoints may remain under `/oauth`.

## Traceability

- Code:
  - `satoidc/satoidc/auth/oidc_keys.py`
  - `satoidc/satoidc/auth/oauth2.py`
  - `satoidc/satoidc/routes/oauth2.py`
  - `satoidc/satoidc/models/__init__.py`
  - `satoidc/migrations/versions/6c2f4c9d1a7e_add_oidc_signing_keys.py`
- Tests:
  - `satoidc/tests/test_oidc_key_rotation.py`
  - `satoidc/tests/test_oauth_metadata.py`
- Docs: this feature folder.
- Decisions: `agent-memory/decisions.md`.
