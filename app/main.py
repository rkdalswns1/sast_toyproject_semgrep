"""FastAPI application entry point."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.analysis.routes import router as analysis_router
from app.auth.routes import router as auth_router
from app.auth.services import bootstrap_administrator
from app.config import Settings
from app.db.database import create_db_engine, create_session_factory, initialize_database
from app.findings.routes import router as findings_router
from app.projects.routes import router as projects_router
from app.rules.routes import router as rules_router
from app.rules.services import seed_kisa_2021_catalog


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings.from_env()
    engine = create_db_engine(app_settings.database_url)
    session_factory = create_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        app_settings.upload_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            app_settings.upload_dir.chmod(0o700)
        initialize_database(engine)
        with session_factory() as session:
            bootstrap_administrator(
                session, email_domain=app_settings.account_email_domain
            )
        with session_factory() as session:
            seed_kisa_2021_catalog(session)
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
    application.include_router(projects_router)
    application.include_router(analysis_router)
    application.include_router(findings_router)
    application.include_router(rules_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
