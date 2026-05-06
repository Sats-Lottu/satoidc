# Test Plan: Rotacao de Chaves OIDC

## Status

- Status: draft
- Created: 2026-05-06
- Updated: 2026-05-06

## Unit Tests

- Deve gerar `kid` unico para novas chaves.
- Deve criar chave nova com `status=validating`.
- Deve impedir duas chaves `active` ao mesmo tempo.
- Deve selecionar exatamente uma chave `active` para assinatura.
- Deve mover chave ativa anterior para `validating` ao ativar outra chave.
- Deve calcular `retired_after` usando TTL maximo de token, cache JWKS e margem extra.
- Deve listar no JWKS apenas chaves `active` e `validating`.
- Deve ocultar chaves `retired` do JWKS.
- Deve serializar somente parametros publicos no JWK publicado.
- Deve registrar eventos de auditoria para criacao, ativacao, rebaixamento, aposentadoria e assinatura.

## Integration Tests

- Emitir token antes da rotacao e capturar `kid` antigo.
- Rotacionar chave e ativar nova `kid`.
- Verificar que o JWKS contem a chave antiga e a nova.
- Validar token antigo usando JWKS apos a rotacao.
- Emitir token novo e verificar que usa a nova `kid`.
- Validar token novo usando JWKS.
- Executar aposentadoria apos `retired_after`.
- Verificar que chave antiga deixa de aparecer no JWKS.
- Verificar que chaves `retired` nao sao usadas para novas assinaturas.
- Verificar que a aplicacao usa a nova chave sem restart.

## API Tests

- `GET /.well-known/openid-configuration` retorna `jwks_uri`.
- `GET /.well-known/jwks.json` retorna `keys`.
- `POST /admin/oidc/keys` cria uma chave para usuario autorizado.
- `POST /admin/oidc/keys/{kid}/activate` ativa a chave e rebaixa a anterior.
- `POST /admin/oidc/keys/rotate` executa criacao e ativacao.
- `POST /admin/oidc/keys/retire-expired` aposenta chaves vencidas.
- `GET /admin/oidc/keys` lista metadados sem material privado.
- Usuario nao autorizado recebe erro apropriado nos endpoints administrativos.

## Security Tests

- `private_jwk`, `private_jwk_encrypted` e equivalentes nao aparecem no JWKS.
- Material privado nao aparece em logs de sucesso ou falha.
- Eventos de auditoria nao incluem material privado.
- Falha no backend criptografico nao vaza segredo em mensagem de erro.
- Rotacao manual exige permissao administrativa.
- Nao e possivel ativar chave inexistente ou `retired`.

## Regression Tests

- Discovery OIDC continua publicando issuer, authorization endpoint, token endpoint e userinfo endpoint.
- Clientes que consomem `jwks_uri` conseguem validar tokens emitidos antes e depois da rotacao.
- Alias de compatibilidade sob `/oauth` continuam funcionando enquanto forem suportados.
