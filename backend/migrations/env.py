from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

from app.database.session import Base
from app.core.config import settings

# Import ALL application models so Alembic can see them
from app.models import (
    User,
    Alert,
    Incident,
    AIAnalysis,
    SOCReport,
    SOARAction,
    SOARActionLog,
    AuditLog,
)


# Alembic configuration
config = context.config


# Configure logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# Metadata used by Alembic autogenerate
target_metadata = Base.metadata

# Tables managed internally by LangGraph.
# Alembic must never create, modify, or delete them.
LANGGRAPH_TABLES = {
    "checkpoints",
    "checkpoint_blobs",
    "checkpoint_writes",
    "checkpoint_migrations",
}


def include_object(
    object_,
    name,
    type_,
    reflected,
    compare_to,
):
    """
    Exclude LangGraph checkpoint tables from Alembic
    autogenerate operations.
    """

    if (
        type_ == "table"
        and name in LANGGRAPH_TABLES
    ):
        return False

    return True


def run_migrations_offline() -> None:
    """
    Run migrations in offline mode.
    """
    url = settings.DATABASE_URL

    context.configure(
    url=url,
    target_metadata=target_metadata,
    literal_binds=True,
    dialect_opts={"paramstyle": "named"},
    compare_type=True,
    include_object=include_object,
)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in online mode.
    """
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.DATABASE_URL

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
    connection=connection,
    target_metadata=target_metadata,
    compare_type=True,
    include_object=include_object,
)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()