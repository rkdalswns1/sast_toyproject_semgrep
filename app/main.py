"""FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.auth.routes import router as auth_router
from app.auth.services import bootstrap_administrator
from app.config import Settings
from app.db.database import create_db_engine, create_session_factory, initialize_database


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings.from_env()
    engine = create_db_engine(app_settings.database_url)
    session_factory = create_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        app_settings.upload_dir.mkdir(parents=True, exist_ok=True)
        initialize_database(engine)
        with session_factory() as session:
            bootstrap_administrator(session)
        yield
        engine.dispose()

    application = FastAPI(title="SAST MVP", lifespan=lifespan)
    application.state.settings = app_settings
    application.state.db_engine = engine
    application.state.session_factory = session_factory
    application.state.templates = Jinja2Templates(
        directory=str(app_settings.template_dir)
    )
    application.mount(
        "/static",
        StaticFiles(directory=str(app_settings.static_dir)),
        name="static",
    )
    application.include_router(auth_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
