from setuptools import find_packages, setup
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="propelauth-fastapi",
    version="2.0.1",
    description="A FastAPI library for managing authentication, backed by PropelAuth",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/propelauth/propelauth-fastapi",
    packages=find_packages(include=["propelauth_fastapi"]),
    author="PropelAuth",
    author_email="support@propelauth.com",
    license="MIT",
    install_requires=["propelauth-py", "requests"],
    setup_requires=["pytest-runner"],
    tests_require=["pytest==4.4.1"],
    test_suite="tests",
)
