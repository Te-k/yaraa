PWD = $(shell pwd)


check:
	pytest
	flake8
	ruff check .

test:
	pytest

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/yaraa.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*
