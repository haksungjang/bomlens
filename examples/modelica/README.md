# Modelica Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates dependency identification for a Modelica (`.mo`) project. cdxgen has no Modelica cataloger, so BomLens instead parses the `annotation(uses(...))` block a `.mo` package declares its dependencies in directly.

## Project Structure

- `Example.mo`: a minimal package with no model body, only a `uses()` declaration

## Dependencies

- **Modelica** (4.0.0): the Modelica Standard Library
- **Buildings** (13.0.0): the Modelica Buildings Library

This is a direct declaration, not a resolved dependency graph: there is no Modelica lockfile to read, so only the libraries a `.mo` file names in its own `uses()` block are identified — no transitive dependencies.

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat` — see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/modelica
../../scripts/scan-sbom.sh --project "ModelicaExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan writes its outputs into a `ModelicaExample_1.0.0/` folder (`ModelicaExample_1.0.0_bom.json` and related files). The SBOM lists the 2 libraries declared in `Example.mo`'s `uses()` block: Modelica and Buildings.
<!-- expected-components: 2-2 -->
