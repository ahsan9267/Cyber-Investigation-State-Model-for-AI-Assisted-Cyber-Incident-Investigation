# Step 3 verification

These files publish existing verification source. Preparing the upload packs did not execute the backend tests or produce a new accuracy result.

## Offline unit checks

From the integrated repository root, after installing the existing requirements, use PowerShell:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location).Path 'src'
python -B -m unittest discover -s tests -p 'test_association*.py' -v
python -B -m unittest discover -s tests -p 'test_ait_dataset.py' -v
python -B -m unittest discover -s tests -p 'test_evidence.py' -v
```

The discovery path makes the test helpers importable. The association tests cover the operational router and the explicitly separate prototype paths, including independent episode, lineage, network, ambiguity and representation controls. The dataset adapter's unit tests use inline examples; evaluating an external dataset requires supplying that dataset separately.

## Evaluation tools

- `tools/check_association_adversarial.py` contains independent controls.
- `tools/evaluate_association.py` evaluates supplied input; inspect its arguments and dataset assumptions.
- `tools/check_evidence_gaps.py` concerns evidence availability rather than proof of a complete attack history.

The files retain their original assertions and output language. Record the actual command, source revision, inputs and result when running them. A historical PASS line is not evidence that a different source revision has passed.

## Interpreting results

Report correct associations, incorrect merges, missed associations and correct separations for the evaluated scope. A synthetic marker demonstrates a processing path, not broad incident-detection accuracy. A unit test does not establish that every policy rule implements a published research method.

The source upload helper checks payload integrity and Git history. Those checks do not execute association logic.
