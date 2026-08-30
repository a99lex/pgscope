from plan_regression import plan_fingerprint


def test_plan_fingerprint_ignores_runtime_costs():
    first = {
        "Plan": {
            "Node Type": "Seq Scan",
            "Relation Name": "orders",
            "Total Cost": 42.0,
            "Actual Total Time": 1.2,
        }
    }
    second = {
        "Plan": {
            "Node Type": "Seq Scan",
            "Relation Name": "orders",
            "Total Cost": 999.0,
            "Actual Total Time": 300.0,
        }
    }

    assert plan_fingerprint(first)[0] == plan_fingerprint(second)[0]


def test_plan_fingerprint_detects_structural_change():
    sequential = {
        "Plan": {
            "Node Type": "Seq Scan",
            "Relation Name": "orders",
        }
    }
    indexed = {
        "Plan": {
            "Node Type": "Index Scan",
            "Relation Name": "orders",
            "Index Name": "orders_pkey",
        }
    }

    assert plan_fingerprint(sequential)[0] != plan_fingerprint(indexed)[0]
