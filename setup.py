import pathlib
import sys

from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

# See https://pytest-runner.readthedocs.io/en/latest/#conditional-requirement
needs_pytest = {"pytest", "test", "ptr"}.intersection(sys.argv)
pytest_runner = ["pytest-runner"] if needs_pytest else []

setup(
    name="propelauth-fastapi",
    version="2.1.20",
    description="A FastAPI library for managing authentication, backed by PropelAuth",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/propelauth/propelauth-fastapi",
    packages=find_packages(include=["propelauth_fastapi"]),
    author="PropelAuth",
    author_email="support@propelauth.com",
    license="MIT",
    install_requires=["propelauth-py==3.1.19", "requests"],
    setup_requires=pytest_runner,
    tests_require=["pytest==4.4.1"],
    test_suite="tests",
)
