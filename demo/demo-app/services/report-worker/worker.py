"""Demo worker: loads report definitions from YAML."""
import requests
import yaml


def load_definition(text: str):
    # PyYAML < 5.4 full_load is affected by CVE-2020-14343 (arbitrary code execution)
    return yaml.full_load(text)


def fetch(url: str):
    return requests.get(url, timeout=5).json()
