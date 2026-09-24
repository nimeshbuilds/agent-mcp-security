# Scan a built container image

<p class="inv-eyebrow">WALKTHROUGH 05 · IMAGE ARCHIVES</p>

Inspect a packaged agent from a saved image archive, without a source checkout or a running container.

<div class="inv-journey-meta" markdown="1">

**You need:** A [prepared workspace](setup.md) with `invscan` on PATH. Stay in the extracted bundle folder or repository root. No AI account is needed. The included archive needs neither Docker nor Podman.

**You will create:** An image report in `scan-report/scenarios/05-image/`.

</div>

## 1. Scan the included image archive

<div class="inv-step" markdown="1">

Use the bundled Docker-save fixture. The limits below comfortably fit this small example.

<!-- invscan-step:05:image_archive -->
```sh
invscan --image-archive examples/images/demo-agent.tar --image-platform linux/amd64 --image-max-archive-bytes 10000000 --image-max-unpacked-bytes 20000000 --image-max-entries 1000 --image-max-layers 10 --report scan-report/scenarios/05-image --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** **3 findings**, **0 coverage gaps**, and exit **1**. `image.container_started` is **false**. The scanner reads the archive and never starts its container.

</div>

</div>
## 2. Open the image findings

<div class="inv-step" markdown="1">

Open `scan-report/scenarios/05-image/report.html` from your workspace.

Read the image information and compare findings from packaged source with findings from image configuration/history and retained layers.

<div class="inv-result" markdown="1">

**You should see** Evidence tied to the packaged artifact. Image configuration findings can still exist when an image has no readable source. Compiled logic, dependency CVEs, signatures and deployed sandbox behavior are outside this scanner’s coverage.

</div>

</div>
## 3. Narrow the image scan

<div class="inv-step" markdown="1">

Run only AI001 against the same archive.

<!-- invscan-step:05:selected_image -->
```sh
invscan --image-archive examples/images/demo-agent.tar --scans AI001 --summary-json
```

<div class="inv-result" markdown="1">

**You should see** **0 findings** and exit **0** for this selected rule. That differs from the full image scan because you intentionally changed the scope. No report files are created by this command.

</div>

</div>
## Optional image exercises

<details class="inv-option" markdown="1">
<summary>See an archive limit fail explicitly</summary>

Make the maximum archive size one byte.

<!-- invscan-step:05:archive_limit -->
```sh
invscan --image-archive examples/images/demo-agent.tar --image-max-archive-bytes 1 --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** An operational error and exit **2**. A rejected archive is not a clean scan.

</div>

</details>
<details class="inv-option" markdown="1">
<summary>Read image-specific help</summary>

Open the image reference in your terminal.

<!-- invscan-step:05:image_help -->
```sh
invscan --help-topic images
```

For your own archives, use Docker-save or OCI-layout tar archives, optionally gzip-compressed. A `docker export` filesystem dump lacks the required image metadata. [Full image guide](../IMAGE_SCANNING.md).

</details>
<details class="inv-option" markdown="1">
<summary>Use your own local image or registry</summary>

These are **conditional alternatives**. Install and start the selected runtime, replace the uppercase placeholder with your real image reference, and run only the route you need. They are not part of the self-contained archive exercise.

With Docker:

```sh
invscan --image YOUR_LOCAL_IMAGE --image-runtime docker --image-timeout 300 --report scan-report/scenarios/05-docker
```

With Podman:

```sh
invscan --image YOUR_LOCAL_IMAGE --image-runtime podman --report scan-report/scenarios/05-podman
```

To explicitly permit a registry pull:

```sh
invscan --image YOUR_REGISTRY_IMAGE --pull --image-platform linux/amd64 --report scan-report/scenarios/05-registry
```

Pulls can require registry credentials and network access. `--image-timeout` applies to runtime pull/export; archive/expanded-byte/entry/layer limits govern archive inspection. Actual results depend on your image. These routes are not claimed to have been exercised against every runtime or registry.

</details>

**Done:** You have an artifact-based report without executing the target. To use your own saved image, replace `examples/images/demo-agent.tar` with its path and select the correct platform.

<div class="inv-journey-nav" markdown="1">

[← Control scan scope](04-scope.md)

[All walkthroughs](../SCENARIOS.md)

[Use gates and baselines →](06-ci.md)

</div>
