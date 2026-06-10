# Contributing to Python Shield WAF

First off, thank you for considering contributing to Python Shield WAF!

## Development Setup

1. Clone the repository and navigate to the directory:
   ```bash
   git clone https://github.com/<your-username>/python-shield-waf.git
   cd python-shield-waf
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   pip install pytest pytest-asyncio pytest-cov ruff
   ```

## Adding New AI Features or Payloads

If you are expanding the dataset or modifying the AI:
1. Add new payloads to `scripts/generate_dataset.py`
2. Run `python scripts/generate_dataset.py`
3. Retrain the models via `python scripts/train_model.py`
4. Do **not** commit the `.pkl` model artifacts unless specifically requested (they are ignored by default).

## Code Standards

* **Linting**: We use `ruff`. Run `ruff check .` before committing.
* **Formatting**: Run `ruff format .` to auto-format code.
* **Tests**: All code must have tests. Run `pytest tests/` and ensure 100% pass rate.

## Pull Request Process

1. Fork the repo and create a new branch (`feature/your-feature-name`).
2. Write tests for your changes.
3. Ensure the test suite passes and code is properly formatted.
4. Open a Pull Request detailing your changes and their motivation.
