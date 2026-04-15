.PHONY: all backend frontend install test clean

REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all: install

install:
	cd $(REPO_ROOT)/backend && python3 -m venv $(REPO_ROOT)/.venv && . $(REPO_ROOT)/.venv/bin/activate && pip install -r requirements.txt
	cd $(REPO_ROOT)/frontend && npm install

backend:
	cd $(REPO_ROOT) && . .venv/bin/activate && uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd $(REPO_ROOT)/frontend && npm run dev

test-backend:
	cd $(REPO_ROOT) && . .venv/bin/activate && python -m pytest tests/ -v

test-frontend:
	cd $(REPO_ROOT)/frontend && npm test

clean:
	rm -f $(REPO_ROOT)/backend/cyberhunter.db
	rm -rf $(REPO_ROOT)/.venv
	rm -rf $(REPO_ROOT)/frontend/node_modules $(REPO_ROOT)/frontend/.next
