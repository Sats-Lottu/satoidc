# Tasks: Rotacao de Chaves OIDC

## Status

- Status: draft
- Created: 2026-05-06
- Updated: 2026-05-06

## Implementation Tasks

1. Criar modelo e migracao `oidc_signing_keys`.
2. Criar modelo ou adaptador de auditoria para eventos `key.*` e `token.signed`.
3. Implementar geracao de `kid` unico e chave RSA `RS256`.
4. Implementar repositorio de chaves com consulta da chave `active` e listagem de chaves publicaveis.
5. Implementar transicao atomica de ativacao:
   - rebaixar chave ativa anterior para `validating`;
   - calcular `retired_after`;
   - ativar nova chave.
6. Substituir a chave RSA em memoria por resolucao dinamica da chave `active`.
7. Garantir que todo JWT emitido tenha header `kid`.
8. Publicar `/.well-known/jwks.json` com somente chaves `active` e `validating`.
9. Atualizar discovery para publicar `jwks_uri` canonico.
10. Implementar endpoints administrativos:
    - `POST /admin/oidc/keys`
    - `POST /admin/oidc/keys/{kid}/activate`
    - `POST /admin/oidc/keys/rotate`
    - `POST /admin/oidc/keys/retire-expired`
    - `GET /admin/oidc/keys`
11. Proteger endpoints administrativos com permissao adequada.
12. Implementar aposentadoria de chaves expiradas.
13. Adicionar logs estruturados sem material privado.
14. Adicionar testes unitarios, integracao e seguranca conforme `test-plan.md`.
15. Documentar configuracoes operacionais de TTL, cache JWKS e backend criptografico.

## Sequencing

1. Persistencia e migracao.
2. Servicos de chave e JWKS sem alterar emissao de tokens.
3. Integracao da emissao de tokens com chave ativa.
4. Endpoints administrativos e auditoria.
5. Aposentadoria e testes de rotacao ponta a ponta.

## Open Questions

- O MVP deve usar Vault Transit desde o inicio ou comecar por banco com chave privada criptografada?
- Qual permissao administrativa deve controlar rotacao manual: `root`, `admin` ou ambas?
- Qual sera o TTL real de ID Token e Access Token apos consolidacao das configuracoes OAuth2?
- As rotas atuais `/oauth/.well-known/openid-configuration` e `/oauth/jwks.json` serao mantidas indefinidamente ou apenas como alias de migracao?
