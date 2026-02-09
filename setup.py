#!/usr/bin/env python
import json
import logging
import os
from importlib import util
from os import path
from pathlib import Path

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py


class PreBuildCommand(build_py):
    """Pre-build command"""

    def transform_graph_yaml_to_json(self) -> None:
        """Transforms YAML graph checks to JSON and copies them to build/lib"""

        import yaml  # can't be top-level, because it needs to be first installed via 'setup_requires'

        graph_check_paths = ("checkov/*/checks/graph_checks",)
        build_path = Path(self.build_lib)
        src_path = Path()

        for graph_check_path in graph_check_paths:
            for yaml_file in src_path.glob(f"{graph_check_path}/**/*.yaml"):
                json_file = (build_path / yaml_file).with_suffix(".json")
                self.mkpath(str(json_file.parent))
                json_file.write_text(json.dumps(yaml.safe_load(yaml_file.read_text())))

    def run(self) -> None:
        self.execute(self.transform_graph_yaml_to_json, ())
        build_py.run(self)


# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

logger = logging.getLogger(__name__)
spec = util.spec_from_file_location(
    "checkov.version", os.path.join("checkov", "version.py")
)
# noinspection PyUnresolvedReferences
mod = util.module_from_spec(spec)
spec.loader.exec_module(mod)  # type: ignore
version = mod.version  # type: ignore

setup(
    cmdclass={
        "build_py": PreBuildCommand,
    },
    setup_requires=[
        "pyyaml",
    ],
    extras_require={
        "dev": [
            "pytest==5.3.1",
            "coverage==5.5",
            "coverage-badge",
            "GitPython==3.1.41",
            "bandit",
            "jsonschema",
        ]
    },
    install_requires=[
        'aiodns==4.0.0',
        'aiohappyeyeballs==2.6.1',
        'aiohttp==3.13.3',
        'aiomultiprocess==0.9.1',
        'aiosignal==1.4.0',
        'annotated-types==0.7.0',
        'anyio==4.12.1',
        'argcomplete==3.6.3',
        'asteval==1.0.6',
        'attrs==25.4.0',
        'bc-detect-secrets==1.4.29',
        'bc-jsonpath-ng==1.5.9',
        'bc-python-hcl2==0.3.51',
        'beautifulsoup4==4.14.3',
        'boolean-py==5.0',
        'boto3==1.42.43',
        'botocore==1.42.43',
        'cached-property==2.0.1',
        'cachetools==7.0.0',
        'certifi==2026.1.4',
        'cffi==2.0.0',
        'charset-normalizer==3.4.4',
        'click==8.3.1',
        'click-option-group==0.5.9',
        'cloudsplaining==0.8.2',
        'colorama==0.4.6',
        'configargparse==1.7.1',
        'cyclonedx-python-lib==3.1.5',
        'decorator==5.2.1',
        'deep-merge==0.0.4',
        'distro==1.9.0',
        'docker==7.1.0',
        'dockerfile-parse==2.0.1',
        'dpath==2.1.3',
        'frozenlist==1.8.0',
        'gitdb==4.0.12',
        'gitpython==3.1.41',
        'h11==0.16.0',
        'httpcore==1.0.9',
        'httpx==0.28.1',
        'idna==3.11',
        'igraph==0.10.8',
        'importlib-metadata==8.7.1',
        'jinja2==3.1.6',
        'jiter==0.13.0',
        'jmespath==1.1.0',
        'jsonschema==4.26.0',
        'jsonschema-specifications==2025.9.1',
        'junit-xml==1.9',
        'lark==1.3.1',
        'license-expression==30.1.0',
        'markdown==3.10.1',
        'markupsafe==3.0.3',
        'multidict==6.7.1',
        'networkx==2.6.3',
        'openai==2.17.0',
        'orjson==3.11.7',
        'packageurl-python==0.17.6',
        'packaging==26.0',
        'ply==3.11',
        'policy-sentry==0.14.2',
        'policyuniverse==1.5.1.20231109',
        'prettytable==3.16.0',
        'propcache==0.4.1',
        'pycares==5.0.1',
        'pycep-parser==0.6.1',
        "pycparser==3.0 ; implementation_name != 'PyPy'",
        'pydantic==2.12.5',
        'pydantic-core==2.41.5',
        'pyparsing==3.3.2',
        'python-dateutil==2.9.0.post0',
        "pywin32==311 ; sys_platform == 'win32'",
        'pyyaml==6.0.3',
        'rdflib==7.5.0',
        'referencing==0.37.0',
        'regex==2025.11.3',
        'requests==2.32.5',
        'rpds-py==0.30.0',
        's3transfer==0.16.0',
        'schema==0.7.8',
        'semantic-version==2.10.0',
        'setuptools==80.10.2',
        'six==1.17.0',
        'smmap==5.0.2',
        'sniffio==1.3.1',
        'sortedcontainers==2.4.0',
        'soupsieve==2.8.3',
        'spdx-tools==0.7.1',
        'tabulate==0.9.0',
        'termcolor==3.3.0',
        'texttable==1.7.0',
        'toml==0.10.2',
        'tqdm==4.67.3',
        'typing-extensions==4.15.0',
        'typing-inspection==0.4.2',
        'unidiff==0.7.5',
        'update-checker==0.18.0',
        'uritools==6.0.1',
        'urllib3==2.6.3',
        'wcwidth==0.5.3',
        'xmltodict==1.0.2',
        'yarl==1.22.0',
        'zipp==3.23.0'
    ],
    dependency_links=[],  # keep it empty, needed for pipenv-setup
    license="Apache License 2.0",
    name="checkov",
    version=version,
    python_requires=">=3.14",
    description="Infrastructure as code static analysis",
    author="bridgecrew",
    author_email="meet@bridgecrew.io",
    url="https://github.com/bridgecrewio/checkov",
    packages=find_packages(
        exclude=[
            "dogfood_tests*",
            "flake8_plugins*",
            "integration_tests*",
            "performance_tests*",
            "tests*",
        ]
    ),
    include_package_data=True,
    package_data={
        "checkov": ["py.typed"],
        "checkov.common.util.templates": ["*.jinja2"],
        "checkov.ansible.checks.graph_checks": ["**/*.json"],
        "checkov.arm.checks.graph_checks": ["**/*.json"],
        "checkov.bicep.checks.graph_checks": ["**/*.json"],
        "checkov.cloudformation.checks.graph_checks": ["**/*.json"],
        "checkov.dockerfile.checks.graph_checks": ["**/*.json"],
        "checkov.github_actions.checks.graph_checks": ["**/*.json"],
        "checkov.kubernetes.checks.graph_checks": ["**/*.json"],
        "checkov.terraform.checks.graph_checks": ["**/*.json"],
    },
    scripts=["bin/checkov", "bin/checkov.cmd"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
        "Typing :: Typed",
    ],
)
