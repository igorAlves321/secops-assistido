# SecOps Assistido

Detecção de anomalias em logs com explicação assistida. O mesmo núcleo de detecção
(`secops_core`) roda em dois modos: local, para desenvolvimento e teste, e híbrido AWS,
para portfólio e produção.

![Arquitetura SecOps Assistido v2](docs/arquitetura-secops-v2.jpg)

## Modos

- **Modo A (local):** gerador de logs, detecção em Python (z-score, Isolation Forest,
  regras de CloudTrail e modelagem de log), explicação por templates Jinja2 e Ollama em
  Docker, persistência em SQLite, API FastAPI e dashboard Streamlit.
- **Modo B (híbrido AWS):** CloudWatch Logs e CloudTrail, EventBridge a cada 5 minutos,
  Lambda, SNS para alertas e DynamoDB (TTL de 14 dias), com a mesma API e o mesmo dashboard.

## Status

Em preparação. O trabalho começa pelo Modo A; o Modo B vem depois que o núcleo estiver
funcionando.

## Ambiente

Docker Compose com a pasta do projeto montada nos containers, para hot reload do código.
Python 3.13 e dependências gerenciadas com [uv](https://docs.astral.sh/uv/).

### Primeiro uso

```bash
docker compose build api
```

Depois, no VS Code, abra o projeto e use **Dev Containers: Reopen in Container**
(`F1`). O editor passa a usar o mesmo Python e as mesmas bibliotecas dos containers.
O build da imagem vem antes porque o serviço `dev` reutiliza a imagem
`secops-assistido:dev` gerada pelo serviço `api`.
