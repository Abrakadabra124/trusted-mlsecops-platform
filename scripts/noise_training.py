"""Development-only bounded-loss fit; never called by a production worker."""

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit

from mlsecops import robust_training
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES


def definition():
    return {
        **robust_training.definition(),
        "algorithm": "clipped-box-generalized-cross-entropy-v1",
        "q": 0.7,
        "linf_budget": 0.10,
        "authority": "validation-development-only",
    }


def objective(parameters, inputs):
    width = len(FEATURES)
    weights = parameters[:width] - parameters[width : 2 * width]
    margin = inputs @ parameters
    q = definition()["q"]
    log_probability = -np.logaddexp(0, -margin)
    powered = np.exp(q * log_probability)
    regularizer = weights / (len(inputs) * definition()["C"])
    loss = float((-np.expm1(q * log_probability) / q).mean() + np.dot(weights, regularizer) / 2)
    gradient = -(inputs.T @ (powered * expit(-margin))) / len(inputs)
    gradient[:width] += regularizer
    gradient[width : 2 * width] -= regularizer
    return loss, gradient


def refit(classifier, features, labels):
    rules = definition()
    if set(np.asarray(labels).tolist()) != {0, 1}:
        raise Rejected("noise_training_requires_two_classes")
    scaler, estimator = (step[1] for step in classifier.steps)
    if estimator.C != 1.0 or estimator.class_weight is not None or not estimator.fit_intercept:
        raise Rejected("noise_training_estimator_profile")
    inputs = robust_training.design(features, labels, scaler, linf_budget=rules["linf_budget"])
    parameters = robust_training.collapse(
        np.r_[estimator.coef_[0], np.zeros(len(FEATURES)), estimator.intercept_[0]]
    )
    initial, _ = objective(parameters, inputs)
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
        raise Rejected("noise_training_solver_failed")
    fitted = robust_training.collapse(result.x)
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
        raise Rejected("noise_training_convergence_unproven")
    width = len(FEATURES)
    estimator.coef_ = (fitted[:width] - fitted[width : 2 * width])[None, :]
    estimator.intercept_ = np.array([fitted[-1]])
    estimator.n_iter_ = np.array([result.nit])
    return {
        "policy_digest": digest(canonical(rules)),
        "training_rows": len(features),
        "iterations": int(result.nit),
        "initial_objective": initial,
        "final_objective": final,
        "projected_gradient_inf": residual,
        "status": "numerically-stationary-not-global-certificate",
    }
