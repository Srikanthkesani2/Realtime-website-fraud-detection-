# -*- coding: utf-8 -*-
"""PyOD MCP Server: Agent interface for anomaly detection.

Exposes PyOD's ADEngine as MCP tools that any LLM agent can call.
Tier A: knowledge queries + stateless planning.

Usage:
    python -m pyod.mcp_server

Note: On Windows with antivirus software (e.g., Bitdefender), the MCP
server subprocess may be blocked. If MCP is unavailable, use ADEngine
directly in Python: ``from pyod.utils.ad_engine import ADEngine``.
"""
# Author: Yue Zhao <yzhao062@gmail.com>
# License: BSD 2 clause

from __future__ import annotations

import importlib.util
import json
import keyword
import os
import sys


def _check_mcp():
    """Probe whether the optional `mcp` package is importable.

    Returns the FastMCP class if available, else None. Does NOT call
    sys.exit — callers decide how to handle the missing-dep case.

    Gotcha: ``importlib.util.find_spec("mcp.server.fastmcp")`` RAISES
    ``ModuleNotFoundError`` when the parent ``mcp`` package is not
    installed (it does not return None in that case). Probe the parent
    first, then the submodule only if the parent exists.
    """
    if importlib.util.find_spec("mcp") is None:
        return None
    try:
        spec = importlib.util.find_spec("mcp.server.fastmcp")
    except ModuleNotFoundError:
        return None
    if spec is None:
        return None
    from mcp.server.fastmcp import FastMCP
    return FastMCP


_engine = None


def _get_engine():
    """Lazy ADEngine singleton for the tool functions."""
    global _engine
    if _engine is None:
        from pyod.utils.ad_engine import ADEngine
        _engine = ADEngine()
    return _engine


def _to_json(obj):
    """Serialize result to JSON string."""
    return json.dumps(obj, indent=2, default=str)


def profile_data(data_path: str, data_type: str = "auto") -> str:
    """Profile a dataset for anomaly detection.

    Loads data from path, detects data type and characteristics.
    Returns a JSON profile for use with plan_detection().

    Args:
        data_path: Path to data file (CSV, NPY, JSON).
        data_type: Override. One of 'tabular', 'text', 'image', or 'auto'.
    """
    X = _load_data(data_path)
    dt = None if data_type == "auto" else data_type
    return _to_json(_get_engine().profile_data(X, data_type=dt))


def plan_detection(
    data_profile: str,
    priority: str = "balanced",
    constraints: str = ""
) -> str:
    """Plan an anomaly detection pipeline.

    Returns a DetectionPlan with detector, params, reason, and evidence.

    Args:
        data_profile: JSON string from profile_data().
        priority: 'speed', 'accuracy', or 'balanced'.
        constraints: Optional JSON, e.g. '{"exclude_detectors": ["ECOD"]}'.
    """
    try:
        profile = json.loads(data_profile)
    except (json.JSONDecodeError, TypeError) as e:
        return _to_json({"error": "Invalid JSON", "details": str(e)})
    if not isinstance(profile, dict):
        return _to_json({"error": "data_profile must be a JSON object"})
    try:
        cons = json.loads(constraints) if constraints else None
    except (json.JSONDecodeError, TypeError) as e:
        return _to_json({"error": "Invalid JSON", "details": str(e)})
    if cons is not None and not isinstance(cons, dict):
        return _to_json({"error": "constraints must be a JSON object"})
    return _to_json(_get_engine().plan_detection(profile, priority, cons))


def build_detector(plan: str) -> str:
    """Get constructor metadata for a detector from a plan.

    Returns import path, class name, params, and a Python code
    snippet for instantiation. Params are passed through from
    the plan without constructor signature validation.

    Args:
        plan: JSON string from plan_detection().
    """
    try:
        plan_dict = json.loads(plan)
    except (json.JSONDecodeError, TypeError) as e:
        return _to_json({"error": "Invalid JSON", "details": str(e)})
    if not isinstance(plan_dict, dict):
        return _to_json({"error": "plan must be a JSON object"})
    engine = _get_engine()
    name = plan_dict.get('detector_name', '')
    algo = engine.kb.get_algorithm(name)
    if algo is None:
        return _to_json({"error": "Unknown detector", "name": name})

    preset = plan_dict.get('preset')
    params = plan_dict.get('params', {})
    if not isinstance(params, dict):
        return _to_json({"error": "params must be a JSON object"})

    # Validate preset is only used with EmbeddingOD
    if preset and name != 'EmbeddingOD':
        return _to_json({"error": "Preset only valid for EmbeddingOD",
                         "detector": name, "preset": preset})

    # Validate preset against known allowlist
    _VALID_PRESETS = {'for_text', 'for_image'}
    if preset and preset not in _VALID_PRESETS:
        return _to_json({"error": "Unknown preset", "preset": preset})

    # Validate param keys are simple identifiers (no injection)
    for key in params:
        if not key.isidentifier() or keyword.iskeyword(key):
            return _to_json({"error": "Invalid parameter name", "key": key})

    if preset:
        code = "from pyod.models.embedding import EmbeddingOD\n"
        param_str = ', '.join('%s=%r' % (k, v) for k, v in params.items())
        code += "clf = EmbeddingOD.%s(%s)" % (preset, param_str)
    else:
        class_path = algo['class_path']
        module_path, class_name = class_path.rsplit('.', 1)
        code = "from %s import %s\n" % (module_path, class_name)
        if params:
            param_str = ', '.join('%s=%r' % (k, v) for k, v in params.items())
            code += "clf = %s(%s)" % (class_name, param_str)
        else:
            code += "clf = %s()" % class_name

    return _to_json({
        "detector_name": name,
        "class_path": algo['class_path'],
        "params": params,
        "preset": preset,
        "code_snippet": code,
    })


def list_detectors(data_type: str = "", status: str = "shipped") -> str:
    """List available PyOD detectors.

    Args:
        data_type: Filter by data type (tabular, text, image, etc.).
        status: Filter by status (shipped, planned, all).
    """
    return _to_json(_get_engine().list_detectors(
        data_type=data_type or None, status=status))


def explain_detector(name: str) -> str:
    """Explain a PyOD detector: how it works, strengths, weaknesses,
    benchmark performance, and recommended use cases."""
    try:
        return _to_json(_get_engine().explain_detector(name))
    except ValueError as e:
        return _to_json({"error": str(e)})


def compare_detectors(
    names: str = "",
    data_type: str = "tabular",
    top_k: int = 3
) -> str:
    """Compare detectors for a given data type.

    Args:
        names: Comma-separated detector names. If empty, top-k for type.
        data_type: Data type to compare for.
        top_k: Number of top detectors.
    """
    name_list = [n.strip() for n in names.split(',')] if names else None
    return _to_json(_get_engine().compare_detectors(name_list, data_type, top_k))


def get_benchmarks(benchmark: str = "all") -> str:
    """Get benchmark results (ADBench, NLP-ADBench, TSB-AD)."""
    return _to_json(_get_engine().get_benchmarks(benchmark))


def _deserialize_result(result_json: str):
    """Parse a `run_detection` JSON result back into a dict.

    Converts the list-form ``scores_train`` / ``labels_train`` /
    ``scores_test`` / ``labels_test`` fields back to numpy arrays so
    the engine's downstream methods can operate on them. Returns
    ``None`` when the input is not a JSON object or when any array
    field contains values that cannot be coerced to the expected
    numeric dtype (e.g., a hand-edited or stale payload from an
    agent).
    """
    import numpy as np
    try:
        result = json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(result, dict):
        return None
    try:
        if ('scores_train' in result
                and result['scores_train'] is not None):
            result['scores_train'] = np.asarray(
                result['scores_train'], dtype=float)
        if ('labels_train' in result
                and result['labels_train'] is not None):
            result['labels_train'] = np.asarray(
                result['labels_train'], dtype=int)
        if ('scores_test' in result
                and result['scores_test'] is not None):
            result['scores_test'] = np.asarray(
                result['scores_test'], dtype=float)
        if ('labels_test' in result
                and result['labels_test'] is not None):
            result['labels_test'] = np.asarray(
                result['labels_test'], dtype=int)
    except (ValueError, TypeError):
        return None
    return result


def run_detection(
    data_path: str,
    plan: str,
    test_data_path: str = ""
) -> str:
    """Run anomaly detection with a given plan.

    Wraps ``ADEngine.run_detection``. The returned JSON omits the
    fitted ``detector`` instance (not JSON-serializable) and converts
    numpy arrays to lists so the result can round-trip through the
    MCP transport. Pass the returned JSON back into
    ``analyze_results`` and ``explain_findings``.

    Args:
        data_path: Path to training data file (CSV, NPY, NPZ, JSON, MAT).
        plan: JSON string from plan_detection().
        test_data_path: Optional path to held-out test data.
    """
    try:
        plan_dict = json.loads(plan)
    except (json.JSONDecodeError, TypeError) as e:
        return _to_json({"error": "Invalid plan JSON", "details": str(e)})
    if not isinstance(plan_dict, dict):
        return _to_json({"error": "plan must be a JSON object"})
    try:
        X_train = _load_data(data_path)
    except (OSError, ValueError) as e:
        return _to_json({"error": "Failed to load training data",
                         "details": str(e)})
    X_test = None
    if test_data_path:
        try:
            X_test = _load_data(test_data_path)
        except (OSError, ValueError) as e:
            return _to_json({"error": "Failed to load test data",
                             "details": str(e)})
    try:
        result = _get_engine().run_detection(
            X_train, plan_dict, X_test=X_test)
    except Exception as e:
        return _to_json({"error": "Detection failed",
                         "type": type(e).__name__,
                         "details": str(e)})
    out = {k: v for k, v in result.items() if k != 'detector'}
    for key in ('scores_train', 'labels_train',
                'scores_test', 'labels_test'):
        val = out.get(key)
        if val is not None and hasattr(val, 'tolist'):
            out[key] = val.tolist()
    return _to_json(out)


def analyze_results(
    result: str,
    data_path: str = "",
    top_k: int = 10
) -> str:
    """Analyze a detection result.

    Wraps ``ADEngine.analyze_results``. Pass the JSON returned by
    ``run_detection`` as ``result``; optionally include the original
    training data path to enable feature-importance analysis.

    Args:
        result: JSON string from run_detection().
        data_path: Optional path to training data for feature importance.
        top_k: Number of top anomalies to return.
    """
    parsed = _deserialize_result(result)
    if parsed is None:
        return _to_json({"error": "Invalid result JSON"})
    X = None
    if data_path:
        try:
            X = _load_data(data_path)
        except (OSError, ValueError) as e:
            return _to_json({"error": "Failed to load data",
                             "details": str(e)})
    try:
        analysis = _get_engine().analyze_results(
            parsed, X=X, top_k=top_k)
    except Exception as e:
        return _to_json({"error": "Analysis failed",
                         "type": type(e).__name__,
                         "details": str(e)})
    return _to_json(analysis)


def explain_findings(
    result: str,
    indices: str = "",
    top_k: int = 5,
    data_path: str = ""
) -> str:
    """Explain why specific samples were flagged as anomalies.

    Wraps ``ADEngine.explain_findings``. Pass the JSON returned by
    ``run_detection`` as ``result``. Provide ``indices`` to explain
    specific rows, or leave it empty to explain the top-k anomalies.

    Args:
        result: JSON string from run_detection().
        indices: Comma-separated 0-based row indices, e.g. "0,5,12".
            Empty means top-k.
        top_k: Number of top anomalies to explain when indices is empty.
        data_path: Optional path to data for feature-level explanations.
    """
    parsed = _deserialize_result(result)
    if parsed is None:
        return _to_json({"error": "Invalid result JSON"})
    idx_list = None
    if indices:
        try:
            idx_list = [int(s.strip()) for s in indices.split(',')
                        if s.strip()]
        except ValueError as e:
            return _to_json({"error": "Invalid indices",
                             "details": str(e)})
    X = None
    if data_path:
        try:
            X = _load_data(data_path)
        except (OSError, ValueError) as e:
            return _to_json({"error": "Failed to load data",
                             "details": str(e)})
    try:
        explanations = _get_engine().explain_findings(
            parsed, indices=idx_list, top_k=top_k, X=X)
    except Exception as e:
        return _to_json({"error": "Explanation failed",
                         "type": type(e).__name__,
                         "details": str(e)})
    return _to_json(explanations)


def _load_data(path):
    """Load data from file path."""
    import numpy as np

    ext = os.path.splitext(path)[1].lower()
    if ext == '.npy':
        return np.load(path, allow_pickle=False)
    elif ext == '.npz':
        data = np.load(path, allow_pickle=False)
        return data[data.files[0]]
    elif ext == '.csv':
        data = np.genfromtxt(path, delimiter=',', skip_header=1)
        # Return features only (last column is label if present)
        if data.ndim == 2 and data.shape[1] > 1:
            return data[:, :-1]
        return data
    elif ext == '.json':
        with open(path, 'r') as f:
            return json.load(f)
    elif ext == '.mat':
        from scipy.io import loadmat
        data = loadmat(path)
        if 'X' in data:
            return data['X']
        for key in data:
            if not key.startswith('_'):
                return data[key]
    else:
        raise ValueError("Unsupported file format: %s" % ext)


_TOOL_FUNCTIONS = (
    profile_data,
    plan_detection,
    build_detector,
    list_detectors,
    explain_detector,
    compare_detectors,
    get_benchmarks,
    run_detection,
    analyze_results,
    explain_findings,
)


def main() -> int:
    """Entry point for `python -m pyod.mcp_server` and `pyod mcp serve`.

    Creates the FastMCP instance, registers every tool function, and
    blocks on mcp.run(). If the `mcp` extra is not installed, print
    an install hint to stderr and return exit code 1.
    """
    FastMCP = _check_mcp()
    if FastMCP is None:
        print(
            "PyOD MCP server requires the 'mcp' package. "
            "Install with: pip install pyod[mcp]",
            file=sys.stderr,
        )
        return 1

    mcp = FastMCP("pyod")
    for fn in _TOOL_FUNCTIONS:
        mcp.tool()(fn)

    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
