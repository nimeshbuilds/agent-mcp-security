# Prepare your walkthrough workspace

<p class="inv-eyebrow">START HERE · ONE-TIME SETUP</p>

Choose the route that matches your installation. You only need to prepare once; keep the same terminal open as you move between walkthroughs.

<div class="inv-journey-meta" markdown="1">

**Already set up?** If `invscan --version` works and your current folder contains `examples/safer`, start with [your first source report](02-source.md).

**Which route?** The native download is enough for walkthroughs 1–7 and the source scan in 10. The full report-editing and local API labs in 8–9 also use repository helper scripts and Python.

</div>

## Native download

<div class="inv-step" markdown="1">

### 1. Download and extract the CLI

Follow [Download or build](../INSTALLATION.md#download-a-standalone-release) to choose your operating system, verify the checksum and extract **the whole archive**. Keep `invscan` and `_internal` together. PDF support and Headroom are included; no separate Python installation is required for the CLI.

</div>

<div class="inv-step" markdown="1">

### 2. Open a terminal in the extracted folder

This is the folder containing `invscan` (or `invscan.exe`), `_internal` and `examples`. Use your file manager's **Open in Terminal** action, or change to that folder in your terminal.

Add this folder to PATH for the current terminal. Choose your shell:

=== "macOS / Linux"

    ```sh
    export PATH="$PWD:$PATH"
    ```

=== "Windows PowerShell"

    ```powershell
    $env:Path = "$((Get-Location).Path);$env:Path"
    ```

Keep this terminal open. The change applies only to this terminal session.

</div>

<div class="inv-step" markdown="1">

### 3. Check the installation

```sh
invscan --version
```

<div class="inv-result" markdown="1">

**You should see** `0.15.0`. Your current folder should contain `examples/safer`, `examples/vulnerable` and `examples/images`. You are ready for [walkthrough 2: your first report](02-source.md).

</div>

</div>

## Source workspace for the full lab

Use this route for **all ten walkthroughs**, including the Python helpers in walkthroughs 8–9. It needs Git and Python **3.10+** for the Headroom lab. It does not need a model account for walkthroughs 1–9.

<div class="inv-step" markdown="1">

### 1. Get the examples and helpers

```sh
git clone https://github.com/nimeshbuilds/invarune.git
```

Move into the new folder:

```sh
cd invarune
```

Already have a checkout? Open a terminal in its root instead. Use the current default branch for these walkthrough pages and their helpers.

</div>

<div class="inv-step" markdown="1">

### 2. Install into a project environment

Choose your platform. Run each line in order; reuse `.venv` only if it already belongs to this project.

=== "macOS / Linux"

    Create an environment:

    ```sh
    python3 -m venv .venv
    ```

    Install the CLI and the lab's PDF/AI packages:

    ```sh
    .venv/bin/python -m pip install '.[ai,pdf]'
    ```

    Activate it in this terminal:

    ```sh
    . .venv/bin/activate
    ```

=== "Windows PowerShell"

    Create an environment:

    ```powershell
    py -3 -m venv .venv
    ```

    Install the CLI and the lab's PDF/AI packages:

    ```powershell
    .\.venv\Scripts\python.exe -m pip install '.[ai,pdf]'
    ```

    Put this environment on PATH for the current terminal; no execution-policy change is needed:

    ```powershell
    $env:Path = "$((Resolve-Path .venv\Scripts).Path);$env:Path"
    ```

</div>

<div class="inv-step" markdown="1">

### 3. Confirm you are ready

```sh
invscan --version
```

<div class="inv-result" markdown="1">

**You should see** `0.15.0`. Stay in this repository folder for every walkthrough. The environment supplies both `invscan` and the `python` command used by the optional lab helpers.

</div>

</div>

## How to follow each walkthrough

- Use the copy button on **one command** at a time, paste it into your terminal, and read the result box before continuing.
- Commands are the same in Bash, Zsh and PowerShell unless a platform tab says otherwise. `# Expected exit 1` or `2` is a comment explaining an intentional outcome.
- Exit **0** means the chosen gate did not fail; **1** means findings met the threshold; **2** means an error or incomplete assessment. None is a security certification.
- Most saved files go under `scan-report/scenarios/`. The guide tells you the exact file to open. Repeating a report command replaces files in its output directory.
- For walkthrough 8, use a fresh lab output directory: `scan-report/scenarios/08-changed-source` must not already exist. Move earlier lab output aside if you are repeating it.

<details class="inv-option" markdown="1">
<summary>How do I read a command's exit code?</summary>

Run the matching command **immediately after** the scan, before another command changes the recorded exit status:

=== "Bash / Zsh"

    ```sh
    echo $?
    ```

=== "PowerShell"

    ```powershell
    $LASTEXITCODE
    ```

Expected nonzero codes are part of the exercises. Run steps individually; do not join a whole walkthrough with `&&` or use a shell setting that stops the session on any nonzero exit.

</details>

[Start your first report →](02-source.md){ .md-button .md-button--primary }
[Choose another walkthrough](../SCENARIOS.md){ .md-button }
