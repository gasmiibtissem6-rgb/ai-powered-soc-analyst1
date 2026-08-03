from fastapi import FastAPI

app = FastAPI(
    title="AI-Powered SOC Analyst API",
    description="Backend API for the intelligent SOC platform",
    version="1.0.0",
)


@app.get("/")
async def root():
    return {
        "message": "AI-Powered SOC Analyst API is running 🚀",
        "status": "ok"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }