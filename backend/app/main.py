from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.routes import router
from app.core.config import get_settings
from app.core.database import SessionLocal, init_db
from app.core.security import hash_password
from app.models import User

settings = get_settings()


def seed_dev_user() -> None:
    if not settings.is_development:
        return
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.username == settings.dev_seed_username))
        if existing is None:
            db.add(
                User(
                    username=settings.dev_seed_username,
                    password_hash=hash_password(settings.dev_seed_password),
                    role="admin",
                )
            )
            db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    seed_dev_user()
    yield


app = FastAPI(
    title=settings.app_name,
    description="Local-first IT assessment platform for authorized MSP use.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)
