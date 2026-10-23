.PHONY: up down restart logs shell status inspect package test lint ci test-in-splunk appinspect fix-perms clean

# Default Splunk admin password from .env
SPLUNK_PASSWORD ?= changeme

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart splunk

fix-perms:
	@docker compose ps | grep -q splunk_to_fusion_dev || { echo "Splunk container is not running. Run 'make up' first." >&2; exit 1; }
	@echo "Fixing app permissions inside the container so Splunk can read the app..."
	# Own runtime dirs by the container's splunk user instead of leaving them
	# world-writable on the host bind mount.
	# shortcut: host user loses direct write access to local/ and metadata/;
	# upgrade by running the container as the host UID/GID when the image supports it.
	@docker compose exec --user root splunk chown -R splunk:splunk /opt/splunk/etc/apps/TA-splunk_to_fusion/local /opt/splunk/etc/apps/TA-splunk_to_fusion/metadata
	@docker compose exec --user root splunk chmod 755 /opt/splunk/etc/apps/TA-splunk_to_fusion/local /opt/splunk/etc/apps/TA-splunk_to_fusion/metadata
	# Make app source readable by the splunk user. certs/ must contain only
	# public CA certificates so Splunk can load them for proxy/TLS validation.
	@docker compose exec --user root splunk bash -c 'cd /opt/splunk/etc/apps/TA-splunk_to_fusion && \
	  find . -type d -not -path "./.git/*" -exec chmod a+rx {} + && \
	  find . -type f -not -path "./.git/*" -not -name ".env" -exec chmod a+r {} +'
	docker compose restart splunk

logs:
	docker compose logs -f splunk

shell:
	docker compose exec splunk /bin/bash

status:
	@echo "Splunk Web:   http://localhost:8000"
	@echo "REST API:     https://localhost:8089"
	@echo "HEC:          https://localhost:8088"
	@docker compose ps

inspect:
	@echo "=== App list ==="
	@docker compose exec splunk sudo -u splunk /opt/splunk/bin/splunk display app -auth admin:$(SPLUNK_PASSWORD) 2>/dev/null || true
	@echo "=== REST endpoint ==="
	@curl -sk -u admin:$(SPLUNK_PASSWORD) https://localhost:8089/servicesNS/nobody/TA-splunk_to_fusion/ta_s2f/broker 2>/dev/null || true

clean:
	@find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@rm -f TA-splunk_to_fusion-*.tar.gz

lint:
	@echo "=== Python syntax checks ==="
	@python3 -B -m py_compile bin/*.py tests/*.py
	@echo "=== Conf file checks ==="
	@python3 -B -c "import configparser; [configparser.ConfigParser().read(f) for f in __import__('glob').glob('default/*.conf')]" && echo "default/*.conf OK"

package:
	@rm -f TA-splunk_to_fusion-1.0.0.tar.gz
	@$(eval STAGING := $(shell mktemp -d))
	@mkdir -p $(STAGING)/TA-splunk_to_fusion
	rsync -a --delete \
	  --exclude='.git*' --exclude='.agents*' --exclude='AGENTS.md' \
	  --exclude='tests' --exclude='__pycache__' --exclude='*.pyc' \
	  --exclude='.env' --exclude='docker-compose.yml' --exclude='Makefile' \
	  --exclude='.github' --exclude='scripts' \
	  ./ $(STAGING)/TA-splunk_to_fusion/
	tar -czf TA-splunk_to_fusion-1.0.0.tar.gz -C $(STAGING) .
	@rm -rf $(STAGING)

test:
	python3 -B -m unittest discover -s tests -v

test-in-splunk:
	@docker compose ps | grep -q splunk_to_fusion_dev || { echo "Splunk container is not running. Run 'make up' first." >&2; exit 1; }
	# Use the container system Python; Splunk's embedded Python needs runtime
	# env vars set by splunkd and fails when invoked directly from the CLI.
	# shortcut: tests run on the system interpreter, not the exact Splunk
	# interpreter; upgrade by wrapping this in splunkd's environment.
	docker compose exec -w /opt/splunk/etc/apps/TA-splunk_to_fusion splunk \
	  /usr/bin/python3 -B -m unittest discover -s tests -v

appinspect: package
	@if ! command -v splunk-appinspect >/dev/null 2>&1; then \
	  echo "splunk-appinspect not found. Install with: pip install splunk-appinspect" >&2; \
	  exit 1; \
	fi
	splunk-appinspect inspect TA-splunk_to_fusion-1.0.0.tar.gz \
	  --included-tags splunk_appinspect \
	  --output-file appinspect_report.json

ci: lint test package
	@echo "=== CI pipeline complete ==="
