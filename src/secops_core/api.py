from fastapi import FastAPI

app = FastAPI(title="SecOps Assistido")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Demonstração do hot reload: tire o "# " das linhas abaixo, salve e abra /ola
# @app.get("/ola")
# def ola() -> dict[str, str]:
#     return {"mensagem": "ola, turma"}
