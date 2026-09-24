# AEGIS T20 Release Candidate - Known Limitations

- Kernel driver subsystems are PRODUCT-PARTIAL (unaudited live kernel
  enforcement); enforcement authority is exercised through
  core/wfp_production.zig + shield/src/pep.rs only.
- Installer ships as NSIS script (installer/aegis.nsi); a packaged .exe
  is produced at cut-over by tools/installer.py --package.
- Pre-existing unrelated pytest ERROR tests/test_e2e.py::test_result.
- bandit / pip-audit are not installed locally; python security posture is
  covered by the security-scan CI job + tests/security suites.
- Release candidate assembled from the working tree at the pinned commit;
  binaries must be rebuilt from source for a production cut.
