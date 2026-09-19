# Built-image fixture

`demo-agent.tar` is a small Docker-save-format archive built deterministically by `tests.image_fixtures.docker_archive`. It contains deliberately risky synthetic Python and fake credentials, including one deleted file revision. It has no configured entrypoint and is for scanner validation, not deployment.

```sh
python3 scan.py --image-archive examples/images/demo-agent.tar --output ./image-report
```

Expected: three high findings (dynamic shell execution, a configured credential, and a retained-layer credential), no extraction/scan gaps, exit 1 with the default high gate. No container runtime or source checkout for the target is required. The archive is not executed.

[Example report](../reports/image/report.md) · [Image guide](../../docs/IMAGE_SCANNING.md)
