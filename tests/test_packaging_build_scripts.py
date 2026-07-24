# -*- coding: utf-8 -*-
"""Validation tests for backend packaging scripts."""

import json
import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_windows_backend_build_script_collects_alphasift_adapter() -> None:
    script = _read_text(REPO_ROOT / "scripts" / "build-backend.ps1")
    main_py = _read_text(REPO_ROOT / "main.py")

    assert "Checking AlphaSift adapter availability" in script
    assert "import alphasift.dsa_adapter" in script
    assert "--collect-all" in script
    assert "alphasift.dsa_adapter" in script
    assert "hiddenImports" in script
    assert "Verifying packaged runtime imports" in script
    assert "DSA_PACKAGED_IMPORT_PROBE" in script
    assert "Start-Process -FilePath $packagedEntry -Wait -PassThru" in script
    assert "$probeProcess.ExitCode" in script
    assert "& $packagedEntry" not in script
    assert "Packaged backend cannot import $module" in script
    assert "DSA_PACKAGED_IMPORT_PROBE" in main_py
    assert "importlib.import_module(_packaged_import_probe)" in main_py


def test_macos_backend_build_script_collects_alphasift_adapter() -> None:
    script = _read_text(REPO_ROOT / "scripts" / "build-backend-macos.sh")
    main_py = _read_text(REPO_ROOT / "main.py")

    assert "Checking AlphaSift adapter availability..." in script
    assert "import alphasift.dsa_adapter" in script
    assert "--collect-all" in script
    assert "cmd+=(\"--collect-all\" \"alphasift\")" in script
    assert "packaged_entry=\"${packaged_root}/stock_analysis\"" in script
    assert "--help" in script
    assert 'DSA_PACKAGED_IMPORT_PROBE="${module}"' in script
    assert "dsa-packaged-import.log" in script
    assert "PathFinder.find_spec(" not in script
    assert "zipfile" not in script
    assert 'normalized.startswith("alphasift/dsa_adapter.")' not in script
    assert "DSA_PACKAGED_IMPORT_PROBE" in main_py
    assert "importlib.import_module(_packaged_import_probe)" in main_py


def test_macos_backend_reports_first_invalid_pyinstaller_signature() -> None:
    script = _read_text(REPO_ROOT / "scripts" / "build-backend-macos.sh")

    assert 'file -b "${packaged_file}" | grep -q "Mach-O"' in script
    assert 'codesign --verify --strict --verbose=4 "${packaged_file}"' in script
    assert "code object is not signed at all" in script
    assert "first invalid signature immediately after PyInstaller packaging" in script
    assert "unreadable signature immediately after PyInstaller packaging" in script


def test_macos_distribution_build_requires_signing_and_notarization() -> None:
    script = _read_text(REPO_ROOT / "scripts" / "build-desktop-macos.sh")
    package = json.loads(
        _read_text(REPO_ROOT / "apps" / "dsa-desktop" / "package.json")
    )

    assert 'if is_true "${GITHUB_ACTIONS:-}"; then' in script
    assert script.index('if is_true "${GITHUB_ACTIONS:-}"; then') < script.index(
        'is_true "${DSA_MAC_DISTRIBUTION}"; then'
    )
    assert 'export CSC_IDENTITY_AUTO_DISCOVERY="true"' in script
    assert "Developer ID Application" in script
    assert "CSC_KEY_PASSWORD is required when CSC_LINK is provided." in script
    assert "APPLE_API_KEY must point to a readable" in script
    assert '--config.forceCodeSigning=true' in script
    assert "CSC_LINK/CSC_KEY_PASSWORD" in script
    assert "APPLE_API_KEY/APPLE_API_KEY_ID/APPLE_API_ISSUER" in script
    assert "APPLE_ID/APPLE_APP_SPECIFIC_PASSWORD/APPLE_TEAM_ID" in script
    assert "WARNING: unsigned local macOS build; do not publish this artifact." in script
    assert package["build"]["mac"]["hardenedRuntime"] is True
    assert package["build"]["mac"]["gatekeeperAssess"] is False


def test_macos_distribution_verifies_app_notarized_dmg_and_gatekeeper() -> None:
    script = _read_text(REPO_ROOT / "scripts" / "build-desktop-macos.sh")

    bundle_verify = script.index(
        'codesign --verify --strict --verbose=4 "${component}"'
    )
    nested_verify = script.index(
        'ERROR: first invalid nested signature after Electron packaging'
    )
    app_verify = script.index(
        'codesign --verify --deep --strict --verbose=4 "${app_path}"'
    )
    developer_id_verify = script.index(
        'grep -q "^Authority=Developer ID Application:"'
    )
    notarize = script.index('xcrun notarytool submit "${dmg_path}" --wait')
    staple = script.index('xcrun stapler staple "${dmg_path}"')
    validate = script.index('xcrun stapler validate "${dmg_path}"')
    mounted_verify = script.index(
        'codesign --verify --deep --strict --verbose=4 "${mounted_app}"'
    )
    gatekeeper = script.index(
        'spctl --assess --type execute --verbose=4 "${mounted_app}"'
    )

    assert bundle_verify < nested_verify < app_verify
    assert app_verify < developer_id_verify < notarize < staple < validate
    assert validate < mounted_verify < gatekeeper


@pytest.mark.parametrize(
    ("extra_env", "expected_error"),
    [
        ({}, "Apple notarization credentials are incomplete."),
        (
            {"CSC_LINK": "developer-id.p12"},
            "CSC_KEY_PASSWORD is required when CSC_LINK is provided.",
        ),
        (
            {"APPLE_API_KEY": "AuthKey_TEST.p8"},
            "App Store Connect API notarization credentials are incomplete.",
        ),
        (
            {"APPLE_ID": "developer@example.com"},
            "Apple ID notarization credentials are incomplete.",
        ),
        (
            {
                "APPLE_API_KEY": "missing-AuthKey_TEST.p8",
                "APPLE_API_KEY_ID": "TEST",
                "APPLE_API_ISSUER": "00000000-0000-0000-0000-000000000000",
            },
            "APPLE_API_KEY must point to a readable",
        ),
    ],
)
def test_macos_distribution_credential_preflight_rejects_partial_sets(
    extra_env: dict[str, str], expected_error: str
) -> None:
    script_path = REPO_ROOT / "scripts" / "build-desktop-macos.sh"
    command = """
source "$1"
uname() { printf 'Darwin\\n'; }
security() { printf '1) Developer ID Application: Test (TEAMID)\\n'; }
prepare_distribution_credentials
"""
    env = {"PATH": os.environ["PATH"], **extra_env}

    result = subprocess.run(
        ["bash", "-c", command, "bash", str(script_path)],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert expected_error in result.stdout
