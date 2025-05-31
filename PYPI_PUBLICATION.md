# Guide to publish fastapi_cookie_auth on PyPI

This guide details the necessary steps to publish the `fastapi_cookie_auth` package on PyPI, allowing other users to install it with pip.

## Prerequisites

1. PyPI account (https://pypi.org/account/register/)
2. Python packaging tools:
   ```bash
   pip install build twine
   ```

## Publication Steps

### 1. Prepare the project

Make sure all necessary files are in place:
- pyproject.toml
- README.md
- LICENSE
- Source code in the `fastapi_cookie_auth/` folder

### 2. Update the version

Each time you publish a new version, update the version number in:
- `fastapi_cookie_auth/__init__.py` → `__version__`
- `pyproject.toml` → `version`

### 3. Build the package

From the project root directory:

```bash
python -m build
```

This will create two files in the `dist/` folder:
- A `.tar.gz` file (source code distribution)
- A `.whl` file (wheel distribution)

### 4. Test the distribution locally (optional but recommended)

Create a virtual environment and test the installation:

```bash
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate
pip install dist/fastapi_cookie_auth-X.Y.Z-py3-none-any.whl
```

Run some tests to verify that everything works correctly.

### 5. Upload to TestPyPI (optional but recommended)

TestPyPI is a separate service that allows you to test the publication:

```bash
python -m twine upload --repository testpypi dist/*
```

You will be asked for your TestPyPI username and password.

To test the installation from TestPyPI:

```bash
pip install --index-url https://test.pypi.org/simple/ fastapi_cookie_auth
```

### 6. Publish on PyPI

Once everything is tested and ready:

```bash
python -m twine upload dist/*
```

You will be asked for your PyPI username and password.

### 7. Verify the installation

After publication, anyone will be able to install the package with:

```bash
pip install fastapi_cookie_auth
```

## Version Updates

For future updates:

1. Make changes to the code
2. Update the version number
3. Build the package again
4. Upload the new version to PyPI

## Using API tokens for authentication

Instead of entering your password each time, you can create an API token:

1. Go to your PyPI account
2. Create an API token
3. Use the token instead of the password when running twine

## Automation with GitHub Actions

To automate publication with GitHub Actions, create a `.github/workflows/publish.yml` file:

```yaml
name: Publish to PyPI

on:
  release:
    types: [created]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build twine
    - name: Build and publish
      env:
        TWINE_USERNAME: ${{ secrets.PYPI_USERNAME }}
        TWINE_PASSWORD: ${{ secrets.PYPI_PASSWORD }}
      run: |
        python -m build
        twine upload dist/*
```

Configure the `PYPI_USERNAME` and `PYPI_PASSWORD` secrets in your GitHub repository.
