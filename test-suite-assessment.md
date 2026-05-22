# Avaliacao da Suite de Testes - SatOIDC

> Relatorio consolidado em 2026-05-22 a partir dos dois arquivos
> `test-suite-assessment.md` encontrados no repositorio. O objetivo e
> transformar as observacoes existentes em um plano pratico para deixar a
> suite mais simples, confiavel e facil de manter.

## 1. Resumo executivo

A suite de testes do SatOIDC esta em um estado bom para o tamanho e o risco
do projeto. Ela ja cobre camadas importantes de seguranca, OIDC/OAuth2,
LNURL-auth, modelos, rotas HTTP, fluxos de setup, propriedades com
Hypothesis, integracao com Testcontainers, e2e com Playwright e smoke de carga
com Locust. A infraestrutura planejada de qualidade tambem ja esta declarada
no `pyproject.toml`, incluindo comandos para testes unitarios, propriedade,
API security, integracao, load e suite completa.

O principal problema nao e ausencia de ferramentas. O problema maior e
organizacao e custo de manutencao: ha setup repetido entre testes, helpers
locais duplicados, alguns testes acoplados a detalhes de implementacao, casos
triviais que geram pouco valor, e uma fronteira ainda pesada entre logica de
negocio, persistencia e UI NiceGUI. Isso aumenta o custo de escrever testes
novos e empurra comportamentos que poderiam ser verificados em unidade para
testes de rota ou e2e.

Prioridade recomendada:

1. Consolidar fixtures e factories compartilhadas.
2. Reduzir duplicacao de usuarios, permissoes, requests e monkeypatches.
3. Separar testes de comportamento de testes de configuracao/contrato.
4. Cobrir lacunas pontuais em servicos de email, assinatura OIDC e fluxos de
   verificacao.
5. Manter Testcontainers para cenarios reais de PostgreSQL, evitando policy
   global de event loop que quebre Playwright no Windows.

## 2. Snapshot atual da suite

Estrutura observada:

```text
satoidc/tests/
  conftest.py
  test_*.py
  api/
  e2e/
  integration/
  load/
  setup/
```

Comandos relevantes declarados:

```text
poetry run task test
poetry run task test_unit
poetry run task test_property
poetry run task test_api_security
poetry run task test_integration
poetry run task test_load
poetry run task test_all
poetry run task test_setup
poetry run task test_e2e
```

O comando padrao `task test` exclui `e2e`, `integration`, `container`, `load`
e `slow`, o que e adequado para feedback rapido. Os testes mais caros ficam em
comandos explicitos.

Dependencias de teste ja presentes e relevantes:

- `pytest`, `pytest-cov`, `pytest-asyncio`
- `hypothesis`
- `testcontainers`
- `factory-boy`
- `playwright`, `pytest-playwright-asyncio`
- `tavern`
- `locust`

Conclusao: nao e necessario criar uma nova estrategia de testes do zero. A
melhoria deve focar em consolidar o que ja existe.

## 3. Pontos fortes

- Boa separacao por tipo de teste: unidade/default, API, integracao, e2e,
  setup e carga.
- Marcadores e tasks tornam explicito o custo de cada camada.
- Uso de `db_session` por teste reduz vazamento de estado.
- Testes de seguranca e tempo sensivel ja existem, incluindo Hypothesis.
- Testcontainers ja esta sendo usado para cenarios onde SQLite nao representa
  o comportamento real.
- Playwright esta reservado para fluxos de usuario, o que evita transformar a
  suite padrao em uma suite lenta.
- As fixtures usam `monkeypatch` e composicao de forma relativamente clara.
- A suite padrao recente passou com `287 passed, 26 deselected`, indicando uma
  base funcional antes das melhorias propostas.

## 4. Problemas prioritarios

| Prioridade | Problema | Impacto | Correcao recomendada |
| --- | --- | --- | --- |
| P1 | Setup repetido de usuarios, admin e permissoes | Aumenta ruido e risco de inconsistencia | Criar fixtures/factories compartilhadas como `make_admin_user`, `make_users` e helpers de permissao |
| P1 | Monkeypatch repetido para rate limit de email token | Deixa testes verbosos e fragiliza mudancas de configuracao | Criar fixture `no_token_rate_limit` |
| P1 | Requests fake duplicados entre testes OAuth e adapters | Cada teste reimplementa contrato parcial | Criar helper unico `make_http_request` ou factory de request compatibilidade FastAPI/Authlib |
| P1 | Testes com tempo real em grants/tokens | Pode gerar flakiness em ambientes lentos | Usar `freezegun` ou fixture `frozen_now` para expiracao e timestamps |
| P1 | Policy de event loop no Windows pode afetar Playwright | `WindowsSelectorEventLoopPolicy` global quebra cenarios async/browser | Manter policy restrita a fixtures que precisam de Testcontainers/PostgreSQL |
| P2 | Testes de configuracao checam strings literais | Quebram com refactor inocente de comandos | Validar comportamento/markers quando possivel |
| P2 | Testes triviais de schema/database | Baixo valor de regressao | Remover, consolidar ou trocar por asserts de contrato real |
| P2 | Alguns testes grandes misturam muitas responsabilidades | Dificulta diagnostico de falha | Separar em testes menores por regra de negocio |
| P2 | UI NiceGUI ainda concentra logica testavel | Forca cobertura via rota/e2e | Extrair servicos/funcoes puras antes de ampliar testes |

## 5. Organizacao e manutencao

### O que esta bom

A divisao de diretorios e adequada. A suite nao deveria ser reorganizada
agressivamente agora, porque isso geraria churn sem atacar o problema central.
O ganho maior esta em helpers compartilhados e reducao de duplicacao dentro da
estrutura atual.

### O que deve mudar

Adicionar um pequeno conjunto de fixtures de dominio em `tests/conftest.py` ou
em modulo auxiliar como `tests/factories.py`, mantendo fixtures especificas nos
subdiretorios quando dependerem de infraestrutura local.

Fixtures/helpers recomendados:

```python
@pytest.fixture
def no_token_rate_limit(monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS", 0)
```

```python
@pytest.fixture
def make_admin_user(make_user):
    def _make_admin_user(**overrides):
        return make_user(is_admin=True, **overrides)

    return _make_admin_user
```

```python
@pytest.fixture
def make_users(make_user):
    def _make_users(count: int, **defaults):
        return [make_user(**defaults) for _ in range(count)]

    return _make_users
```

Tambem vale criar um helper unico para requests de baixo nivel usados por
OAuth/Authlib, evitando duplicacao entre `test_oauth_routes.py` e
`test_fastapi_oauth2_adapters.py`.

### Factory Boy

`factory-boy` ja esta instalado. Ele deve ser usado onde houver criacao
repetida de entidades com muitos campos ou relacionamentos, especialmente
usuarios, clientes OAuth, permissoes e tokens. Para objetos simples, fixtures
leves ainda sao preferiveis a uma camada de factory excessiva.

## 6. Cobertura por area

| Area | Estado | Observacao |
| --- | --- | --- |
| Validadores e seguranca basica | Bom | Mantem boa relacao custo/beneficio |
| LNURL-auth | Bom, mas sensivel a tempo | Usar congelamento de tempo em mais casos |
| OAuth2/OIDC grants e metadata | Bom | Ampliar cenarios de erro e expiracao |
| Rotas OAuth | Bom | Reduzir duplicacao de requests fake |
| Setup wizard | Bom e em expansao | Manter unit/setup/e2e separados |
| UI autenticada/admin | Parcial | E2E cobre fluxo, mas logica deve migrar para servicos testaveis |
| Email tokens | Bom | Falta melhorar fixture de rate limit |
| Email delivery | Lacuna | Criar testes unitarios para sucesso, erro, TLS/auth e configuracao ausente |
| OIDC signing backends | Parcial | Ampliar erros de decrypt/Transit/OpenBao e fallback |
| PostgreSQL/Testcontainers | Bom para integracao | Usar apenas em testes que precisam de comportamento real do banco |
| Tavern/API security | Basico | Evoluir para contratos negativos e headers de seguranca |
| Load smoke | Basico | Manter como smoke, nao como gate padrao |

## 7. Simplificacoes recomendadas

1. Consolidar helpers de usuario.

   Arquivos como `test_permission_requests.py` e
   `test_admin_dashboard_services.py` nao deveriam manter criacao local de
   usuario quando ja existe `make_user` ou quando uma factory compartilhada
   resolveria o caso.

2. Consolidar monkeypatch de rate limit.

   Testes de token de email que precisam ignorar intervalo minimo devem usar
   uma fixture nomeada. Isso deixa claro que a regra esta sendo desativada
   intencionalmente naquele teste.

3. Trocar tempo real por tempo congelado.

   `int(time.time())` em testes de grant/token deve ser substituido por
   `freezegun` ou fixture equivalente. Isso tambem melhora a leitura dos
   cenarios de expiracao.

4. Reduzir testes de baixo valor.

   Testes que apenas confirmam que uma funcao retorna uma sessao ou que um
   modulo legado foi removido devem ser reavaliados. Eles podem ser removidos
   quando nao protegem um contrato publico ou migrados para testes de contrato
   mais relevantes.

5. Parametrizar cenarios repetitivos.

   Casos de segredo, configuracao, escopos, permissoes e payloads similares
   devem usar `pytest.mark.parametrize` quando a diferenca for somente entrada
   e resultado esperado.

6. Separar testes grandes.

   Testes de rota administrativa de chave OIDC e alguns fluxos de setup devem
   ser divididos por comportamento: permissao, validacao, persistencia,
   resposta de erro e caminho feliz.

## 8. Testcontainers e PostgreSQL

Para testes que dependem de semantica real de banco, como migracoes,
concorrencia, locking, constraints e comportamento especifico de PostgreSQL,
usar fixture com Testcontainers e correto.

Recomendacao importante para Windows:

- Nao aplicar `WindowsSelectorEventLoopPolicy` globalmente no `conftest.py`.
- Restringir essa policy a fixture que inicializa PostgreSQL/Testcontainers,
  quando necessario.
- Manter Playwright/e2e fora dessa alteracao global, porque a policy pode
  interferir nos loops async usados pelo navegador.

Isso preserva compatibilidade entre integracao com container e testes e2e.

## 9. NiceGUI, UI e acoplamento

Os testes de UI devem continuar existindo, mas a suite nao deve depender deles
para validar regra de negocio. Sempre que uma pagina NiceGUI acumular
validacao, decisao de permissao, transformacao de dados ou persistencia, a
regra deve ser extraida para servico/helper testavel por unidade.

Exemplos de direcao:

- Rotas/paginas: responsaveis por renderizar, coletar input e chamar servicos.
- Servicos: responsaveis por regras, validacao de dominio e persistencia.
- Testes unitarios: cobrem servicos e helpers.
- Testes e2e: cobrem fluxo do usuario, navegacao, regressao visual basica e
  integracao de componentes.

Essa separacao reduz a necessidade de e2e para cada edge case.

## 10. Plano de execucao

### Imediato

1. Criar fixtures `no_token_rate_limit`, `make_admin_user`, `make_users` e
   helper compartilhado de request OAuth/Authlib.
2. Refatorar testes que duplicam esses setups.
3. Substituir tempo real por `freezegun` em grants/tokens.
4. Revisar `test_quality_testing_config.py` para reduzir asserts em strings
   literais.
5. Remover ou consolidar testes triviais em `test_schemas.py` e
   `test_database.py` quando nao protegerem contrato publico.

### Proximo ciclo

1. Cobrir `services/email_delivery.py` com testes unitarios.
2. Ampliar falhas de assinatura OIDC/OpenBao Transit.
3. Adicionar testes negativos de API security com Tavern quando houver
   contratos estaveis.
4. Quebrar testes grandes de admin/setup por responsabilidade.
5. Criar factories `factory-boy` apenas para entidades com setup repetitivo.
6. Documentar no `agent-memory/` os comandos validados e o cuidado com
   Testcontainers no Windows.

### Opcional

1. Avaliar mutation testing para validadores e regras de seguranca.
2. Medir tempo por teste e marcar casos lentos com `slow`.
3. Criar smoke e2e minimo para autorizacao OIDC quando o fluxo estabilizar.
4. Avaliar snapshot/visual regression apenas para paginas criticas, se houver
   regressao visual recorrente.

## 11. Criterios de aceite para uma suite melhor

A suite pode ser considerada em estado melhor quando:

- Novos testes de usuario/permissao usam fixtures compartilhadas.
- Testes de email token nao repetem monkeypatch de rate limit.
- Testes de grant/token nao dependem de relogio real.
- Helpers de request OAuth/Authlib nao estao duplicados.
- Testes triviais foram removidos ou substituidos por contratos relevantes.
- `task test` continua rapido e sem depender de Docker ou navegador.
- `task test_integration` cobre PostgreSQL real via Testcontainers.
- `task test_e2e` continua isolado e sem dependencia de policy global de event
  loop.
- Lacunas de `email_delivery` e signing backends foram cobertas.

## 12. Conclusao

O SatOIDC ja tem uma suite de testes acima da media para um projeto Python
FastAPI/NiceGUI com OIDC e LNURL-auth. A melhoria agora deve ser cirurgica:
menos duplicacao, mais fixtures de dominio, menos acoplamento a detalhes de
implementacao, mais controle de tempo e mais cobertura nos servicos que ainda
estao pouco protegidos.

A recomendacao e nao expandir a suite antes de simplificar a base de fixtures.
Sem essa etapa, cada novo teste tende a copiar setup antigo e aumentar o custo
de manutencao.
