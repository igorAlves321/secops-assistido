from fastapi import FastAPI

app = FastAPI(title="SecOps Assistido")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
