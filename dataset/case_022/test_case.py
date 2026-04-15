from vulnerable import run_npm_script
import os
import pytest
import json

@pytest.fixture
def setup_project_dir(tmp_path):
    # Create a temporary directory to simulate a project directory
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    
    # Create a package.json file with a sample script
    package_json_content = {
        "scripts": {
            "test": "echo 'Running tests'"
        }
    }
    package_json_path = project_dir / "package.json"
    with open(package_json_path, "w", encoding="utf-8") as f:
        json.dump(package_json_content, f)
    
    return project_dir

def test_run_npm_script_valid_script(setup_project_dir):
    project_dir = setup_project_dir
    result = run_npm_script(str(project_dir), "test")
    assert result == 0

def test_run_npm_script_invalid_script(setup_project_dir):
    project_dir = setup_project_dir
    result = run_npm_script(str(project_dir), "nonexistent")
    assert result == -2