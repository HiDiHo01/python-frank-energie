[![Run Frank Energie Query](https://github.com/HiDiHo01/python-frank-energie/actions/workflows/run_query.yml/badge.svg)](https://github.com/HiDiHo01/python-frank-energie/actions/workflows/run_query.yml)
# python-frank-energie

Asyncio package to communicate with Frank Energie. This package is created to be used with https://github.com/HiDiHo01/home-assistant-frank_energie.

## Disclaimer

This package is not developed, nor supported by Frank Energie.

## Installation
```bash
python3 -m pip install python-frank-energie
```

## Contributing
This repo uses [Python Poetry](https://python-poetry.org) to easily run CI/CD scripts using a local environment. In combination with pre-commet you can make sure the PR passes the checks the first time.

1. Clone and enter this repo
1. Install poetry using `pip install poetry`
1. Install the environment using `poetry install`

When making a commit, pre-commit runs to check, format and test the code. If everything passes you can push the changes via a Pull request. There GitHub Actions will check if you did everything right and it will notify me. Feel free to ask me to review your PR.

Some nice or useful commands:
- `poetry shell` -> Run commands like `pytest test` with the correct environment, no need to prefix commands with `poetry run ...`
- `(poetry run) pytest tests` -> Runs the unit tests
- `(poetry run) pre-commit run --all-files` -> Run all pre-commit steps on all files.
- `git commit -n ...` -> The `-n` flag allows you to ignore the pre-commit result and make a commit, useful when you want to commit drafts. All commits form a PR will be squashed so you can do this any time.
