import importlib.metadata

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES


def definition():
    return {
        "schema_version": 1,
        "algorithm": "clipped-box-logistic-v1",
        "mutable_features": ["change_size", "change_entropy"],
        "linf_budget": 0.05,
        "domain": [0.0, 1.0],
        "C": 1.0,
        "solver": "L-BFGS-B",
        "maxiter": 500,
        "ftol": 1e-12,
        "gtol": 1e-8,
        "accepted_projected_gradient": 1e-5,
    }


def design(features, labels, scaler):
    features, labels = np.asarray(features), np.asarray(labels)
    if (
        features.ndim != 2
        or features.shape[1] != len(FEATURES)
        or not 1 <= len(features) <= 20000
        or features.dtype.kind not in "fiu"
        or not np.isfinite(features).all()
        or (features < 0).any()
        or (features > 1).any()
        or labels.shape != (len(features),)
        or labels.dtype.kind not in "iu"
        or not np.isin(labels, [0, 1]).all()
    ):
        raise Rejected("robust_training_input")
    features = features.astype(np.float64)
    means, scales = np.asarray(scaler.mean_), np.asarray(scaler.scale_)
    if (
        means.shape != (len(FEATURES),)
        or scales.shape != means.shape
        or not np.isfinite(means).all()
        or not np.isfinite(scales).all()
        or (scales <= 0).any()
    ):
        raise Rejected("robust_training_scaler")
    standardized = (features - means) / scales
    signed = 2 * labels.astype(np.float64) - 1
    budget = np.zeros(len(FEATURES))
    budget[[FEATURES.index(name) for name in definition()["mutable_features"]]] = definition()[
        "linf_budget"
    ]
    lower, upper = np.minimum(budget, features) / scales, np.minimum(budget, 1 - features) / scales
    positive_cost = np.where(signed[:, None] == 1, lower, upper)
    negative_cost = np.where(signed[:, None] == 1, upper, lower)
    return np.column_stack(
        (
            signed[:, None] * standardized - positive_cost,
            -signed[:, None] * standardized - negative_cost,
            signed,
        )
    )


def collapse(parameters):
    width = len(FEATURES)
    weights = parameters[:width] - parameters[width : 2 * width]
    return np.r_[np.maximum(weights, 0), np.maximum(-weights, 0), parameters[-1]]


def objective(parameters, inputs):
    width = len(FEATURES)
    weights = parameters[:width] - parameters[width : 2 * width]
    margin = inputs @ parameters
    regularizer = weights / (len(inputs) * definition()["C"])
    loss = float(np.logaddexp(0, -margin).mean() + np.dot(weights, regularizer) / 2)
    gradient = -(inputs.T @ expit(-margin)) / len(inputs)
    gradient[:width] += regularizer
    gradient[width : 2 * width] -= regularizer
    return loss, gradient


def refit(classifier, features, labels):
    if set(np.asarray(labels).tolist()) != {0, 1}:
        raise Rejected("robust_training_requires_two_classes")
    scaler, estimator = (step[1] for step in classifier.steps)
    if estimator.C != 1.0 or estimator.class_weight is not None or not estimator.fit_intercept:
        raise Rejected("robust_training_estimator_profile")
    inputs = design(features, labels, scaler)
    parameters = collapse(
        np.r_[estimator.coef_[0], np.zeros(len(FEATURES)), estimator.intercept_[0]]
    )
    initial, _ = objective(parameters, inputs)
    rules = definition()
    result = minimize(
        objective,
        parameters,
        args=(inputs,),
        jac=True,
        method=rules["solver"],
        bounds=[(0, None)] * (2 * len(FEATURES)) + [(None, None)],
        options={name: rules[name] for name in ("maxiter", "ftol", "gtol")},
    )
    if (
        not result.success
        or np.asarray(result.x).shape != parameters.shape
        or not np.isfinite(result.x).all()
        or (result.x[:-1] < 0).any()
        or not 0 <= result.nit <= rules["maxiter"]
    ):
        raise Rejected("robust_training_solver_failed")
    fitted = collapse(result.x)
    final, gradient = objective(fitted, inputs)
    projected = gradient.copy()
    projected[:-1] = np.where(fitted[:-1] == 0, np.minimum(projected[:-1], 0), projected[:-1])
    residual = float(np.max(np.abs(projected)))
    if (
        not np.isfinite(final)
        or not np.isfinite(residual)
        or final > initial + 1e-12
        or residual > rules["accepted_projected_gradient"]
    ):
        raise Rejected("robust_training_convergence_unproven")
    width = len(FEATURES)
    estimator.coef_ = (fitted[:width] - fitted[width : 2 * width])[None, :]
    estimator.intercept_ = np.array([fitted[-1]])
    estimator.n_iter_ = np.array([result.nit])
    return {
        "schema_version": 1,
        "algorithm": rules["algorithm"],
        "policy_digest": digest(canonical(rules)),
        "training_rows": len(features),
        "scipy_version": importlib.metadata.version("scipy"),
        "iterations": int(result.nit),
        "initial_objective": initial,
        "final_objective": final,
        "projected_gradient_inf": residual,
        "status": "numerically-converged",
    }
