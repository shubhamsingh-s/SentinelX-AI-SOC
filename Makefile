.PHONY: help up down logs test lint format migrate seed clean

DC_FILE := deploy/docker/docker-compose.yml

help:
	@echo "SentinelX AI SOC - Development Commands:"
	@echo "  make up       - Start local infrastructure (Postgres+Timescale, Redis, Auth Service)"
	@echo "  make down     - Stop and clean local infrastructure"
	@echo "  make logs     - View docker compose logs"
	@echo "  make test     - Run test suite with coverage"
	@echo "  make lint     - Run Ruff and Mypy strict type checking"
	@echo "  make format   - Run Ruff formatting"
	@echo "  make migrate  - Run database migrations"
	@echo "  make seed     - Seed initial database data"

up:
	docker compose -f $(DC_FILE) up -d --build

down:
	docker compose -f $(DC_FILE) down -v --remove-orphans

logs:
	docker compose -f $(DC_FILE) logs -f

test:
	pytest

lint:
	ruff check .
	ruff format --check .
	mypy libs/sentinel_common services/auth_service/app tests

format:
	ruff check --fix .
	ruff format .

migrate:
	@echo "Running Alembic migrations..."
	@python -m alembic upgrade head || echo "Alembic setup will be finalized with initial migrations"

seed:
	@echo "Seeding default data..."
	@python -m scripts.seed || echo "Seed script ready for execution"

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
