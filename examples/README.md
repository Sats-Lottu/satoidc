# Examples – SatoIDC Clients (NiceGUI)

Este diretório contém **exemplos de Relying Parties (OIDC Clients)** integrando com o **SatOIDC** utilizando exclusivamente **NiceGUI**.

---

## 🎯 Objetivo

Os exemplos mostram como:

* Configurar um cliente OIDC
* Redirecionar para `/authorize`
* Receber `authorization_code`
* Trocar código por tokens no `/token`
* Validar o `id_token`
* Consumir o endpoint `/userinfo`
* Manter sessão autenticada na aplicação NiceGUI

---

## 🧱 Arquitetura do Fluxo

```text
NiceGUI App (Client)
        │
        ▼
   SatoIDC (/authorize)
        │
        ▼
 Redirect + code
        │
        ▼
   SatOIDC (/token)
        │
        ▼
     ID Token + Access Token
```

---

## ⚙️ Pré-requisitos

* Python 3.11+
* SatOIDC rodando localmente (ex: `http://localhost:8000`)
* Cliente previamente registrado no SatOIDC

---

## ▶️ Executando um exemplo

```bash
cd examples
python basic_client.py
```

ou

```bash
cd examples
python public_client.py
```

Aplicação disponível normalmente em:

```
http://localhost:8001
```

---

## 🔑 Configuração Necessária

No exemplo `basic_client`, configure:

```python
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
```

O `redirect_uri` configurado no SatOIDC deve coincidir com o definido no exemplo.

---

## 🧪 O que cada exemplo demonstra

| Exemplo           | Foco                            |
| ----------------- | ------------------------------- |
| `basic_client`    | Login OIDC mínimo funcional     |
| `public_client`   | Login OIDC usando PKCE          |

---

## 🧠 Observações Técnicas

* Todos utilizam **Authorization Code Flow**
* HTTPS é obrigatório em ambiente de produção

---

## 🛡️ Segurança

Para uso real:

* Utilize HTTPS
* Não exponha `client_secret` no frontend

---

Esses exemplos servem como base para integrar o SatOIDC em aplicações web modernas baseadas em NiceGUI.
