from setuptools import setup, find_packages

setup(
    name="fastapi_cookie_auth",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.95.0",
        "starlette>=0.26.0",
        "pydantic>=1.10.0",
    ],
    python_requires=">=3.7",
    description="Cookie-based authentication for FastAPI applications",
    author="Reinaldo Arsenio Lorenzo Trujillo",
    author_email="reiarseni@gmail.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
