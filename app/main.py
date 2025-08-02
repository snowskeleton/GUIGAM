from fastapi import FastAPI
import uvicorn

from app.database import create_tables
from app.routes import auth, admin, main_pages

app = FastAPI(title="GAM Web Interface", version="1.0.0")

@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    create_tables()

# Include routers
app.include_router(main_pages.router, tags=["pages"])
app.include_router(auth.router, prefix="/auth", tags=["authentication"])
app.include_router(admin.router, prefix="/admin", tags=["admin"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)