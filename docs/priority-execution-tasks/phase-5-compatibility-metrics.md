# Phase 5: Compatibility And Metrics

Status: open
Priority: P3
Recommended agents: OIDC integration, observability

## Task 5.1: Create Relying-Party Compatibility Matrix

1. Clear task name: Create practical relying-party compatibility matrix.
2. Technical objective: document interoperability with common OIDC clients.
3. Detailed scope: Authlib client, Django, Auth.js/NextAuth, Grafana, Gitea,
   MinIO, oauth2-proxy, or a smaller first batch chosen by maintainers.
4. Required inputs: `specs/flows/relying-party-examples.md`, `examples/`,
   OIDC contract, conformance docs.
5. Expected outputs: compatibility matrix with client type, auth method,
   redirect URI behavior, scopes, and token expectations.
6. Dependencies: conformance evidence recommended.
7. Completion criteria: at least the first selected integrations are documented
   with tested or explicitly pending status.
8. Validation/test criteria: at least one executable example or manual verified
   integration.
9. Recommended specialized agent: OIDC integration agent.
10. Priority: P3.
11. Estimated complexity: M/L.
12. Technical risks: creating examples that are too broad to maintain.
13. Potentially affected files/components: `examples/`, docs, README.
14. Contracts/interfaces involved: OIDC Contract.
15. Integration notes: keep unsupported stacks marked as pending, not implied
    support.

### Subtasks

- Pick the first two integrations.
- Create configuration examples.
- Verify login/token/UserInfo behavior.
- Document limitations.

## Task 5.2: Specify Prometheus-Compatible Metrics Baseline

1. Clear task name: Specify metrics baseline.
2. Technical objective: define metrics before implementing an exporter.
3. Detailed scope: auth attempts, token issuance, failures, LNURL callbacks,
   email send failures, Transit failures, and admin mutation counts.
4. Required inputs: `specs/features/operational-observability/spec.md`,
   structured logging implementation.
5. Expected outputs: metrics spec with names, labels, cardinality rules, and
   privacy constraints.
6. Dependencies: structured logging baseline.
7. Completion criteria: every proposed metric has stable labels and avoids
   user/client/IP high-cardinality leaks unless explicitly justified.
8. Validation/test criteria: design review for cardinality and privacy.
9. Recommended specialized agent: observability engineer.
10. Priority: P3.
11. Estimated complexity: M.
12. Technical risks: high-cardinality labels or sensitive data in metrics.
13. Potentially affected files/components: observability spec and docs only in
    this task.
14. Contracts/interfaces involved: Operational Observability Baseline.
15. Integration notes: implementation should be a separate later task.

### Subtasks

- Define metric names.
- Define allowed labels.
- Mark forbidden labels and sensitive fields.
- Decide whether `/metrics` requires protection or deployment-level controls.

