# SatOIDC

**Satoshi OpenID Connect 1.0 Provider**

---

## 🚀 Overview

**SatOIDC** é um provedor **OpenID Connect 1.0 (OIDC)** que implementa autenticação baseada em Bitcoin/Lightning por meio do protocolo LNURL-auth, mantendo compatibilidade com o ecossistema OpenID Connect.

O projeto implementa o papel de **OpenID Provider (OP)** conforme especificado pelo padrão OpenID Connect 1.0, possibilitando:

* Autenticação federada
* Emissão de ID Tokens (JWT)
* Fluxos OAuth 2.0 compatíveis
* Integração com aplicações web modernas

---

## 🧱 Arquitetura

```text
┌───────────────┐
│   Client App  │
│ (Relying Party)│
└───────┬───────┘
        │ Authorization Request
        ▼
┌─────────────────────┐
│      SatOIDC        │
│  OpenID Provider    │
├─────────────────────┤
│ Authorization EP    │
│ Token EP            │
│ UserInfo EP         │
│ JWKS EP             │
└─────────────────────┘

```

---

## 🔐 Protocol Support

SatOIDC implementa:

* ✅ OAuth 2.0 Authorization Framework
* ✅ OpenID Connect 1.0 Core
* ✅ Discovery (`.well-known/openid-configuration`)
* ✅ JWKS Endpoint
* ✅ ID Token (JWT assinado)
* ✅ PKCE (opcional / recomendado)
* ✅ Refresh Tokens

---

## 📡 Endpoints

| Endpoint                                  | Descrição              |
| ----------------------------------------- | ---------------------- |
| `/authorize`                              | Authorization Endpoint |
| `/oauth/token`                            | Token Endpoint         |
| `/oauth/userinfo`                         | UserInfo Endpoint      |
| `/oauth/.well-known/openid-configuration` | OIDC Discovery         |
| `/oauth/jwks.json`                        | Chaves públicas        |

---

## 🔑 ID Token

O ID Token segue o padrão JWT:

```json
{
  "iss": "https://satoidc.example.com",
  "sub": "user-public-key-or-identifier",
  "aud": "client_id",
  "exp": 1710000000,
  "iat": 1709990000,
  "nonce": "xyz"
}
```

### Assinatura

* Algoritmo recomendado: `RS256`
* Chaves expostas via endpoint JWKS

---

## 🛠️ Instalação

```bash
git clone https://github.com/Sats-Lottu/satoidc.git
cd satoidc
poetry install
poetry run alembic upgrade head
```

---

## ⚙️ Configuração

Exemplo de arquivo `.env`:

```env
OAUTH2_JWT_SECRET_KEY=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
SESSION_MIDDLEWARE_SECRECT_KEY=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
```

---

## ▶️ Execução

```bash
cd satoidc
poetry run fastapi dev satoidc
```

Servidor disponível em:

```
http://localhost:8000
```

---

## 🔍 Descoberta OIDC

```bash
curl http://localhost:8000/oauth/.well-known/openid-configuration
```

Resposta esperada:

```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "...",
  "token_endpoint": "...",
  "userinfo_endpoint": "...",
  "jwks_uri": "...",
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

---

## 🔄 Fluxos Suportados

### Authorization Code Flow (recomendado)

```text
Client → /authorize → User Auth → Code → /token → ID Token
```

### Implicit Flow (opcional)

```text
Client → /authorize → ID Token direto
```

---

## 🧩 Integração com Cliente OIDC

Exemplos completos de integração como **Relying Party (Client)** estão disponíveis na pasta:

```
/examples
```

O diretório contém aplicações de exemplo demonstrando como configurar um cliente OIDC apontando para o SatOIDC via `/.well-known/openid-configuration`, incluindo:

* Registro de client
* Authorization Code Flow
* Validação de ID Token
* Consumo do endpoint `/userinfo`

Consulte a pasta `examples` no repositório para instruções de execução e configuração específicas de cada exemplo.

---

## 🛡️ Segurança

* Tokens assinados (JWT)
* Suporte a PKCE
* HTTPS obrigatório em produção
* Proteção contra replay via nonce

---

## 📚 Conformidade

SatOIDC segue:

* OpenID Connect Core 1.0

* OAuth 2.0 – RFC 6749

* JSON Web Token (JWT) – RFC 7519

* JSON Web Key (JWK) – RFC 7517

* OAuth 2.0 Authorization Server Metadata – RFC 8414

* Proof Key for Code Exchange (PKCE) – RFC 7636

A camada de Authorization Server é construída utilizando **[Authlib](https://pypi.org/project/Authlib/)**, biblioteca madura para implementação de OAuth 2.0, OpenID Connect e JOSE (JWT, JWK, JWS) em Python.

O Authlib é utilizado como motor de protocolo (emissão e validação de tokens, fluxos OAuth/OIDC e assinatura JWT) embora não tenha suporte nativo para Fastapi.


---

## 🧪 Testes

```bash
task test
```

---

## 🧭 Roadmap

* [ ] Integração com LNURL-auth
* [ ] Integração com Nostr
* [ ] Refatoração quando Authlib tiver suporte nativo para Fastapi
* [ ] Implementar Rotação de chaves

---

## 🤝 Contribuição

1. Fork
2. Crie uma branch
3. Commit
4. Pull Request

---

## 📄 Licença

MIT License

---

## ₿ Filosofia

> “Don’t trust. Verify.”

SatOIDC nasce com a proposta de unir **identidade federada tradicional (OIDC)** com os princípios de soberania individual inspirados por Satoshi Nakamoto.

