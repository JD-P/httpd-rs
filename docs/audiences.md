---
doc_type: project
audience: documentation-contributor
status: normative
---

# Users and documentation priorities

Use these user stories to select and order documentation work. Do not select a
topic only because the implementation contains a feature.

## Current priority one: security-conscious Apache operator

This user operates an Apache 2.4 deployment. A new incident, an accumulated
security concern, or a review requirement has made the user consider a
different server implementation.

This user must be able to:

1. Identify whether the incident affects code or semantics that httpd-rs uses.
2. Identify the remaining risk in httpd-rs, the application, and the operating
   environment.
3. test the existing Apache configuration with no service change;
4. identify unsupported behavior and required compatibility capabilities;
5. evaluate the site through httpd-rs;
6. switch the service with a tested rollback procedure;
7. verify TLS, authentication, dynamic handlers, logs, and application flows.

Documentation for this user has the highest priority.

## Current priority two: contributor or coding agent

This user changes httpd-rs itself. The user can be a human contributor, a
maintainer returning to unfamiliar code, or an AI coding agent working from a
bounded task.

This user must be able to:

1. understand the design intuitions that connect otherwise local decisions;
2. identify the authority or invariant that a component preserves;
3. distinguish deliberate incompatibility from missing implementation work;
4. select the correct evidence for a security claim;
5. find the proof, test, ledger, and deployment obligations affected by a
   change;
6. recognize when a convenient local fix violates a system-wide boundary;
7. leave an explanation that survives the implementation task that produced
   it.

Contributor explanations have the same current priority as migration
documentation. They use normal technical prose, not the controlled language
used for operator procedures. Their purpose is to communicate the ideas that
generate the architecture, including tradeoffs and rejected alternatives.

The two priority audiences need different views of the same decision. The
operator needs to know what httpd-rs will do and what remains at risk. The
contributor needs to know why the boundary has its present shape and which
other parts of the system depend on it.

## Later priority: application operator

This user owns an application such as WordPress, Nextcloud, Grafana, or
JupyterLab. The user might not own the host platform.

This user must be able to:

1. Select a supported static, CGI, FastCGI, or reverse-proxy topology.
2. Separate immutable application code from writable application data.
3. Configure the backend identity and public authority correctly.
4. Verify a real application workflow through httpd-rs.
5. Understand behavior during reload and failure.

Each tutorial for this user must use a named application and a complete
deployment. General rules belong in how-to or explanation pages.

## Later priority: security reviewer

This user evaluates a claim before approving a deployment.

This user must be able to:

1. find the threat model and trust boundaries;
2. distinguish proved properties from tested properties;
3. find external assumptions and unsupported surfaces;
4. trace a behavior claim to an executable contract or engineering record;
5. reproduce the relevant test.

## Later priority: package or platform operator

This user installs, switches, monitors, reloads, and removes services.

This user must be able to:

1. identify platform and filesystem requirements;
2. understand which files the package changes;
3. test a configuration before a service transition;
4. recover the previous Apache service state;
5. preserve certificate renewal and log rotation.

These later-priority audiences remain important. Current documentation work
can serve them when it also strengthens one of the two priority paths or closes
a serious operational gap.
