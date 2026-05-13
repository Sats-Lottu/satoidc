# Tasks: Rotacao de Chaves OIDC

## Status

- Status: implemented
- Created: 2026-05-06
- Updated: 2026-05-13

## Implementation Tasks

1. [x] Criar modelo e migracao `oidc_signing_keys`.
2. [x] Criar modelo ou adaptador de auditoria para eventos `key.*` e `token.signed`.
3. [x] Implementar geracao de `kid` unico e chave RSA `RS256`.
4. [x] Implementar repositorio de chaves com consulta da chave `active` e listagem de chaves publicaveis.
5. [x] Implementar transicao atomica de ativacao:
   - rebaixar chave ativa anterior para `validating`;
   - calcular `retired_after`;
   - ativar nova chave.
6. [x] Substituir a chave RSA em memoria por resolucao dinamica da chave `active`.
7. [x] Garantir que todo JWT emitido tenha header `kid`.
8. [x] Publicar `/.well-known/jwks.json` com somente chaves `active` e `validating`.
9. [x] Atualizar discovery para publicar `jwks_uri` canonico.
10. [x] Implementar endpoints administrativos:
    - `POST /admin/oidc/keys`
    - `POST /admin/oidc/keys/{kid}/activate`
    - `POST /admin/oidc/keys/rotate`
    - `POST /admin/oidc/keys/retire-expired`
    - `GET /admin/oidc/keys`
11. [x] Proteger endpoints administrativos com permissao adequada.
12. [x] Implementar aposentadoria de chaves expiradas.
13. [x] Adicionar logs estruturados sem material privado.
14. [x] Adicionar testes unitarios, integracao e seguranca conforme `test-plan.md`.
15. [x] Documentar configuracoes operacionais de TTL, cache JWKS e backend criptografico.

## Sequencing

1. Persistencia e migracao.
2. Servicos de chave e JWKS sem alterar emissao de tokens.
3. Integracao da emissao de tokens com chave ativa.
4. Endpoints administrativos e auditoria.
5. Aposentadoria e testes de rotacao ponta a ponta.

## Open Questions

- O MVP comecou por banco com chave privada criptografada; Vault Transit permanece como evolucao de producao.
- Rotacao manual aceita `admin` ou `root`; `root` continua autorizando tudo.
- A retencao atual usa `OAUTH2_TOKEN_EXPIRES_IN + OIDC_JWKS_CACHE_TTL_SECONDS + OIDC_KEY_RETENTION_MARGIN_SECONDS`.
