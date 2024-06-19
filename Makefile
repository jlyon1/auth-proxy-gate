.PHONY: help migrate migrate-down

# help target should appear first so it's the default
help: ## this list
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

migrate: ## Run Database Migrations
	@migrate -database 'sqlite3://accounts.db' -path ./migrations up

migrate-down: ## Run down db migrations
	@migrate -database 'sqlite3://accounts.db' -path ./migrations down
