.PHONY: test lint fmt validate security ci

PYTHONPATH := lambdas/src

test:
	PYTHONPATH=$(PYTHONPATH) pytest -q

lint:
	ruff check lambdas tests scripts
	ruff format --check lambdas tests scripts

fmt:
	ruff format lambdas tests scripts
	terraform -chdir=terraform fmt -recursive

validate:
	terraform -chdir=terraform init -backend=false -input=false
	terraform -chdir=terraform validate
	tflint --chdir=terraform --init
	tflint --chdir=terraform --recursive --config=$$(pwd)/terraform/.tflint.hcl

security:
	checkov -d terraform --framework terraform --compact --quiet --download-external-modules false

ci: lint test validate security
