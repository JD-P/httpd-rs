#!/usr/bin/env python3
"""Generate and check the explicit Verus proof-strategy inventory.

The inventory is deliberately derived from every `proof fn` in the verified
crate.  Component and epistemic classifications are review metadata; exact
preconditions and postconditions remain in the linked source.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "crates" / "verified" / "src" / "lib.rs"
DOCUMENT = ROOT / "docs" / "proof-strategies.md"
PROOF_START = re.compile(r"(?m)^\s*(?:pub\s+)?proof\s+fn\s+([A-Za-z0-9_]+)")


@dataclass(frozen=True)
class Proof:
    name: str
    line: int
    header: str
    body: str


COMPONENT_RANGES = (
    (1, 541, "Configuration and cache generations"),
    (542, 688, "Backend endpoint identity"),
    (689, 1106, "URI path canonicalization"),
    (1107, 1291, "Percent encoding"),
    (1292, 1541, "Authority parsing"),
    (1542, 2141, "Rewrite target and sink classification"),
    (2142, 2381, "Authorized plan and FastCGI identity"),
    (2382, 2641, "Transform capability and terminal sink admission"),
    (2642, 2721, "Descriptor and inode stability"),
    (2722, 2879, "Rewrite query, restart, map and backreference policy"),
    (2880, 3612, "PCRE2 positive grammar"),
    (3613, 4163, "PCRE2 semantic AST and nginx regex bridge"),
    (4164, 4278, "Cache invalidation and disk identity"),
    (4279, 4384, "Configured input-size gates"),
    (4385, 4534, "Request resource admission"),
    (4535, 4744, "MultiViews admission and authorization"),
    (4745, 4894, "Access-program and regex work accounting"),
    (4895, 5134, "Rewrite filesystem containment"),
    (5135, 5308, "Expression and path matching"),
    (5309, 5414, "Shared memory, maps and queues"),
    (5415, 5669, "Dependency and TLS call boundaries"),
    (5670, 6076, "Generic resource-budget admission"),
    (6077, 6156, "Cancellation boundaries"),
    (6157, 6386, "Hierarchical resource accounting"),
    (6387, 6646, "Worker and output ownership"),
    (6647, 6796, "Request body phase machine"),
    (6797, 7196, "Dynamic outcome lifecycle"),
    (7197, 7796, "Internal requests, redirects and recovery"),
    (7797, 7896, "Body, retry and expression-file admission"),
    (7897, 8286, "Rewrite rule transitions"),
    (8287, 9036, "Rewrite program machine"),
    (9037, 9138, "Access-file selection"),
    (9139, 9236, "Policy-bit meet"),
    (9237, 9346, "Options, handler and authorization configuration"),
    (9347, 9446, "Authentication identity and cache"),
    (9447, 9526, "Authorization providers and override categories"),
    (9527, 9686, ".htaccess admission"),
    (9687, 10346, "Cache-key and lookup identity"),
    (10347, 10508, "Header and token syntax"),
    (10509, 10896, "HTTP/1 framing and byte ranges"),
    (10897, 11606, "Proxy request serialization"),
    (11607, 12146, "Header and range parsing"),
    (12147, 12758, "CGI and mapping bounds"),
    (12759, 13056, "Compression resource policy"),
    (13057, 13086, "Client quota identity"),
    (13087, 13166, "Service and process identity"),
    (13167, 13311, "CGI/backend response admission"),
    (13312, 13596, "CGI environment and regex admission"),
    (13597, 13842, "Cache lookup and expression authorization"),
    (13843, 14047, "Proxy identity and authorization algebra"),
    (14048, 14300, "Authorization evaluator"),
    (14301, 14827, "Configuration phase ordering"),
    (14828, 15940, "Whole request-policy state machine"),
    (15941, 16207, "Policy compilation fold"),
    (16208, 16837, "Configuration merge helpers"),
    (16838, 17166, "RemoteIP and virtual-host identity"),
    (17167, 17391, "Nginx route-index refinement"),
    (17392, 17472, "Dependency and TLS call boundaries"),
    (17473, 18414, "Configuration front-end refinement"),
    (18415, 18602, "Container-field merge"),
    (18603, 21557, "HTTP/2 admission and lifecycle"),
    (21558, 21810, "Access/cache prefilters and mapping order"),
    (21811, 23311, "fnmatch semantics"),
    (23312, 23510, "Handler and CGI capability admission"),
    (23511, 23645, "Authentication-file and FastCGI path immutability"),
    (23646, 24110, "Nginx lexer and parser refinement"),
    (24111, 24421, "Nginx route-index refinement"),
    (24422, 24561, "Nginx lowering closure"),
    (24562, 24711, "Nginx transformation language"),
    (24712, 24911, "Source-neutral scope merge"),
    (24912, 25103, "Common-IR request refinement"),
    (25104, 25474, "Hierarchical lease transactions"),
)


# Line ranges preserve the established broad inventory.  New composition
# projects deliberately override them by theorem name so their review rows do
# not disappear into the older neighboring component when source moves.
COMPONENT_OVERRIDES = {
    "cache_transaction_step_preserves_invariant": "Cache transaction state machine",
    "retired_cache_transaction_cannot_serve_or_publish": "Cache transaction state machine",
    "invalidated_cache_transaction_cannot_serve_or_publish": "Cache transaction state machine",
    "cache_hit_requires_current_reauthorized_generation": "Cache transaction state machine",
    "cache_publication_requires_current_reauthorized_generation": "Cache transaction state machine",
    "pcre_source_certificate_covers_every_byte_and_event": "PCRE2 source grammar refinement",
    "lease_ownership_step_preserves_invariant": "Resource lease ownership",
    "lease_queue_task_and_output_require_acquisition": "Resource lease ownership",
    "lease_cancellation_preserves_live_owner": "Resource lease ownership",
    "lease_terminal_release_is_exactly_once": "Resource lease ownership",
    "expression_cursor_advance_strictly_decreases_remaining": "Expression parser cursor",
    "expression_cursor_depth_is_bounded": "Expression parser cursor",
    "expression_cursor_nonterminal_event_strictly_decreases_work_rank": "Expression parser cursor",
    "expression_cursor_finish_is_total_only_at_terminal_cursor": "Expression parser cursor",
    "fnmatch_class_body_start_subrange": "fnmatch iterative refinement",
    "fnmatch_class_end_subrange": "fnmatch iterative refinement",
    "fnmatch_tokens_refine_recursive_at": "fnmatch iterative refinement",
    "fnmatch_token_spec_unfold": "fnmatch iterative refinement",
    "fnmatch_tokens_refine_recursive_spec": "fnmatch iterative refinement",
    "hierarchical_lease_step_preserves_invariant": "Hierarchical lease transactions",
    "hierarchical_lease_resize_updates_every_enabled_level": "Hierarchical lease transactions",
    "hierarchical_lease_rebind_preserves_owned_primary_and_physical": "Hierarchical lease transactions",
    "hierarchical_lease_release_zeroes_every_level": "Hierarchical lease transactions",
    "hierarchical_lease_terminal_release_is_exactly_once": "Hierarchical lease transactions",
    "hierarchical_lease_pair_resize_is_atomic": "Hierarchical lease transactions",
}


STRATEGIES = {
    "definition": (
        "Definitional SMT consequence",
        "The proof body is empty or nearly empty. Verus unfolds a small Boolean/enum specification "
        "and SMT proves the stated implication. This checks the model's internal consequence, not "
        "that the model is complete or that every runtime caller supplies truthful facts.",
        4,
    ),
    "finite_cases": (
        "Finite case split over the model",
        "SMT and/or an explicit `match` exhaust the modeled enum/Boolean cases. This is exact for "
        "the declared transition or projection, but runtime representation and call-site coverage "
        "remain separate obligations.",
        6,
    ),
    "state_machine": (
        "Finite-state invariant/case analysis",
        "The transition relation is a closed enum/record model and Verus proves an invariant, an "
        "absorbing state, or a gate-order consequence by exhaustive symbolic cases. Strong within "
        "the model; only as strong in production as the executable refinement and event coverage.",
        7,
    ),
    "h2_state_machine": (
        "HTTP/2 executable state-machine refinement",
        "The closed HTTP/2 model is checked across its admitted events and its executable reducers "
        "are consumed by the vendored frame, HPACK, stream, counter and flow-control paths. This is "
        "strong implementation evidence for those transitions; generated Huffman tables, container "
        "library semantics, async scheduling and kernel I/O remain outside the theorem.",
        7,
    ),
    "induction": (
        "Structural induction over a mathematical sequence",
        "The body recurses on a decreasing sequence/index and establishes the property for arbitrary "
        "length. This is a real unbounded proof of the specification; the remaining risk is whether "
        "the executable parser/loop is fully refined to that specification.",
        7,
    ),
    "refined_induction": (
        "Structural induction plus executable refinement",
        "The theorem uses induction over arbitrary input and is paired with an executable loop whose "
        "postcondition is the same specification. This gives comparatively strong implementation "
        "evidence, while allocation, library and OS semantics remain trusted.",
        8,
    ),
    "bitvector": (
        "Exact bit-vector algebra",
        "Verus's bit-vector solver proves the fixed-width mask identity for every input value. This "
        "is exact for the operation; the principal remaining question is whether production uses the "
        "proved operation at every relevant merge.",
        8,
    ),
    "finite_domain": (
        "Exhaustive finite-domain algebra",
        "The proof enumerates a genuinely finite byte/digit domain or composes injective finite "
        "encodings. The mathematical claim is exact; production strength still depends on the "
        "executable encoder/parser refining the same definitions.",
        7,
    ),
    "sequence_algebra": (
        "Quantified sequence/prefix algebra",
        "Explicit quantified assertions prove the property for arbitrary sequence lengths without "
        "testing a finite sample. This is strong for the mathematical path/framing relation; the "
        "runtime's construction of those sequences remains the refinement boundary.",
        7,
    ),
    "arithmetic_gate": (
        "Admission inequality restatement",
        "The admission predicate already requires an overflow-safe inequality; SMT shows that a "
        "successful admission therefore lies under the configured limit. It does not prove that the "
        "chosen limit is safe or that the charged quantity equals real CPU, memory or I/O.",
        4,
    ),
    "cost_model": (
        "Estimated/calibrated cost model plus arithmetic",
        "This is, candidly, a charge estimate followed by a proof that the estimated factors multiply "
        "or sum to at most the budget. Verus proves the arithmetic, not that the estimate upper-bounds "
        "the dependency or all adversarial data shapes.",
        3,
    ),
    "dependency_constants": (
        "Measured/dependency constants plus arithmetic",
        "Fixed limits were selected from dependency limits and adversarial measurements, then Verus "
        "shows those numbers fit the declared envelope. This does not derive a worst case from the "
        "dependency implementation and should be treated as a monitored assumption.",
        2,
    ),
    "concrete_oracle": (
        "Concrete examples only",
        "The solver unfolds the recursive matcher for a small hand-picked set of examples. These are "
        "useful regression oracles, not a general conformance proof and not evidence that unlisted "
        "cases agree with Apache.",
        2,
    ),
}


BITVECTOR_PROOFS = {
    "bits_meet_never_grants",
    "bits_meet_commutative",
    "bits_meet_associative",
    "bits_meet_idempotent",
    "bits_meet_narrowing",
    "options_conjoin_never_grants",
    "options_add_preserves_and_adds",
    "options_remove_never_grants_and_clears",
    "client_quota_ipv6_key_has_zero_host",
    "client_quota_ipv6_key_preserves_prefix",
}

ARITHMETIC_GATE_PROOFS = {
    "autoindex_append_stays_bounded",
    "bcrypt_extreme_cost_rejected",
    "ssha_oversize_salt_rejected",
    "expr_regex_oversize_rejected",
    "regex_match_work_is_bounded",
    "admitted_glob_work_is_bounded",
    "admitted_response_headers_are_bounded",
    "admitted_access_program_is_bounded",
    "bounded_expansion_append_stays_bounded",
    "cache_memory_admission_is_bounded",
    "shared_map_success_is_bounded",
    "shared_queue_success_is_bounded",
    "dependency_call_success_is_bounded",
    "resource_budget_admission_is_bounded",
    "resource_budget_rejects_exhausted",
    "hierarchical_resource_admission_is_bounded",
    "hierarchical_three_scope_success_is_bounded",
    "hierarchical_weighted_rate_success_is_bounded",
    "inline_dynamic_worker_preserves_static_reserve",
    "request_body_memory_admission_is_bounded",
    "expr_file_read_admission_is_bounded",
    "admitted_transform_append_is_bounded",
}

COST_MODEL_PROOFS = {
    "nginx_route_selection_charge_includes_matcher_bytes",
    "regex_expanded_charge_bounds_counted_repetition",
    "regex_optional_repeat_charge_bounds_pike_work",
    "regex_multipass_charge_bounds_all_passes",
}

DEPENDENCY_CONSTANT_PROOFS = {
    "mtls_dependency_shape_is_bounded",
    "outbound_tls_dependency_shape_is_bounded",
}

CONCRETE_ORACLE_PROOFS = {
    "fnmatch_location_glob_oracle",
    "fnmatch_class_negation_oracle",
}

FINITE_DOMAIN_PROOFS = {
    "hex_digit_char_roundtrip",
    "hex_digit_char_injective",
    "hex_byte_spec_injective",
    "lemma_lower_tchar",
}

SEQUENCE_ALGEBRA_PROOFS = {
    "path_under_base_reflexive",
    "path_under_base_transitive",
    "cache_fingerprint_field_injective",
    "lemma_has_header_range_snoc",
    "lemma_no_byte_range_to_seq",
    "lemma_split_root_ok",
    "bytes_contains_subrange",
}

STATE_MACHINE_COMPONENTS = {
    "Authorization evaluator",
    "Cache transaction state machine",
    "Expression parser cursor",
    "Request body phase machine",
    "Resource lease ownership",
    "Dynamic outcome lifecycle",
    "Rewrite rule transitions",
    "Rewrite program machine",
    "Whole request-policy state machine",
    "Policy compilation fold",
    "Nginx lexer and parser refinement",
    "Hierarchical lease transactions",
}

FINITE_CASE_COMPONENTS = {
    "Rewrite target and sink classification",
    "Transform capability and terminal sink admission",
    "Rewrite query, restart, map and backreference policy",
    "Cache invalidation and disk identity",
    "MultiViews admission and authorization",
    "Worker and output ownership",
    "Internal requests, redirects and recovery",
    "Options, handler and authorization configuration",
    "Authentication identity and cache",
    "Authorization providers and override categories",
    ".htaccess admission",
    "CGI/backend response admission",
    "CGI environment and regex admission",
    "Cache lookup and expression authorization",
    "RemoteIP and virtual-host identity",
    "Handler and CGI capability admission",
    "Authentication-file and FastCGI path immutability",
    "Nginx route-index refinement",
    "Nginx lowering closure",
    "Nginx transformation language",
    "Source-neutral scope merge",
    "Common-IR request refinement",
}

REFINED_INDUCTION_PROOFS = {
    "lemma_all_path_bytes_concat",
    "lemma_append_segment",
    "percent_encode_identity",
    "percent_encode_from_identity",
    "percent_encode_no_masked_raw",
    "lemma_last_colon_found",
    "lemma_last_colon_none",
    "cache_key_hex_spec_len",
    "cache_key_hex_spec_head",
    "cache_key_hex_spec_tail",
    "cache_key_hex_spec_injective",
    "fnmatch_tokens_refine_recursive_spec",
}


ACRONYMS = {
    "acl": "ACL",
    "ast": "AST",
    "ascii": "ASCII",
    "bcrypt": "bcrypt",
    "cgi": "CGI",
    "fastcgi": "FastCGI",
    "fnmatch": "fnmatch",
    "h2": "HTTP/2",
    "htaccess": ".htaccess",
    "hir": "HIR",
    "ipv6": "IPv6",
    "mtls": "mTLS",
    "nginx": "nginx",
    "pcre": "PCRE",
    "pcre2": "PCRE2",
    "pid": "PID",
    "posix": "POSIX",
    "qsd": "QSD",
    "ssha": "SSHA",
    "tls": "TLS",
    "url": "URL",
    "utf8": "UTF-8",
}


PROPERTY_OVERRIDES = {
    "cache_transaction_step_preserves_invariant": (
        "Every admitted cache lookup, reauthorization, hit/miss, store, publication, reload, "
        "invalidation, abandonment, and completion transition preserves the transaction invariant."
    ),
    "retired_cache_transaction_cannot_serve_or_publish": (
        "A cache transaction retired by a reload admits no later serving or publication event."
    ),
    "invalidated_cache_transaction_cannot_serve_or_publish": (
        "A transaction fenced by targeted invalidation admits no later serving or publication event."
    ),
    "cache_hit_requires_current_reauthorized_generation": (
        "A cache hit can reach Served only after current-generation reauthorization and an entry "
        "from that same generation."
    ),
    "cache_publication_requires_current_reauthorized_generation": (
        "Publication can reach Published only for the request's current generation and targeted-"
        "invalidation serial."
    ),
    "pcre_source_certificate_covers_every_byte_and_event": (
        "A finished PCRE source certificate covers the exact admitted source length and exactly "
        "one grammar event per contiguous lexer event."
    ),
    "lease_ownership_step_preserves_invariant": (
        "Every admitted acquisition, queue, task, output, cancellation, and release transition "
        "preserves the move-only lease invariant."
    ),
    "lease_queue_task_and_output_require_acquisition": (
        "Queued, running, output, and queued-output phases all retain an acquired unreleased owner."
    ),
    "lease_cancellation_preserves_live_owner": (
        "Cancellation marks a live lease without releasing the capacity still owned by its work."
    ),
    "lease_terminal_release_is_exactly_once": (
        "A released lease has exactly one release and rejects a second release transition."
    ),
    "expression_cursor_advance_strictly_decreases_remaining": (
        "Every admitted expression-parser byte advance strictly reduces the remaining source."
    ),
    "expression_cursor_depth_is_bounded": (
        "Every admitted recursive parser entry remains within the configured depth limit."
    ),
    "expression_cursor_nonterminal_event_strictly_decreases_work_rank": (
        "Every admitted nonterminal parser event consumes finite work rank, including a backward "
        "speculative restore."
    ),
    "expression_cursor_finish_is_total_only_at_terminal_cursor": (
        "The parser accepts Finish exactly when every source byte is consumed and recursion depth "
        "has returned to zero."
    ),
    "fnmatch_tokens_refine_recursive_spec": (
        "For arbitrary patterns and values, the token semantics used by the iterative matcher "
        "equals the original recursive fnmatch specification."
    ),
    "admitted_pcre_ast_has_one_closed_root": (
        "An admitted normalized PCRE AST certificate is bound to the source, nonempty, "
        "single-rooted, and cannot report more captures than nodes."
    ),
    "admitted_pcre_ast_lowering_uses_only_the_declared_match_policy": (
        "An admitted AST lowering exactly round-trips the normalized HIR and selects "
        "leftmost-first matching with backtracking disabled."
    ),
    "lemma_all_path_bytes_concat": (
        "Concatenating two all-path-byte sequences preserves the all-path-byte predicate."
    ),
    "lemma_append_segment": (
        "Appending an admitted segment to a canonical path preserves canonical-path structure."
    ),
    "lemma_last_colon_found": (
        "The recursive authority scan returns the final colon when one exists at the supplied index."
    ),
    "lemma_last_colon_none": (
        "The recursive authority scan returns no colon when the scanned prefix contains none."
    ),
    "lemma_all_tchars_index": (
        "A sequence accepted as all HTTP token characters has a token character at every valid index."
    ),
    "lemma_has_header_range_snoc": (
        "Extending a header search range by one position adds exactly that final position."
    ),
    "lemma_lower_tchar": "ASCII lowercasing preserves the HTTP token-character predicate.",
    "lemma_no_byte_range_to_seq": (
        "A byte excluded from a source range is excluded from the corresponding subsequence."
    ),
    "lemma_split_root_ok": "The root path `/` satisfies the path-splitting invariants.",
    "combine_and_commutative": "Authorization AND-combination is commutative in the model.",
    "combine_or_commutative": "Authorization OR-combination is commutative in the model.",
    "authorization_terminal_prefix_is_absorbing": (
        "Once an authorization fold reaches its kind-specific terminal result, no later active "
        "or inactive child can change the completed decision."
    ),
    "require_none_fold_never_grants": (
        "Completing any invariant-preserving RequireNone fold cannot return Granted."
    ),
    "complete_policy_compilation_visits_every_component_once": (
        "A complete policy-compilation state has traversed all eleven components and retains "
        "exactly the parent, child, or header-admission error condition."
    ),
    "auth_merge_kind_properties": (
        "Authorization merge mode selects AND/OR only with a parent and otherwise selects replacement."
    ),
    "classify_access_rule_properties": (
        "Access rules are classified as conditional, Files, or other from the modeled flags."
    ),
    "nginx_regex_modifiers_are_the_shared_pcre_modes": (
        "nginx `~` and `~*` select only the shared PCRE matcher's case bit; UTF/UCP stay off "
        "and the subject is the normalized URI."
    ),
    "nginx_regex_compile_bridge_preserves_modifier": (
        "A compiled nginx regex profile preserves the source modifier's case bit and keeps "
        "UTF/UCP disabled."
    ),
    "nginx_regex_bridge_uses_the_exact_normalized_subject": (
        "A successful nginx regex bridge includes both the compiled-mode refinement and the "
        "fact that the matcher receives the exact normalized URI bytes."
    ),
    "hierarchical_lease_step_preserves_invariant": (
        "Every admitted resize, scope rebind, and terminal release preserves the lease-local "
        "hierarchical counter-vector invariant."
    ),
    "hierarchical_lease_resize_updates_every_enabled_level": (
        "A resize assigns the new owned quantity to the process level and every enabled client, "
        "filesystem, or request level, while assigning the declared file-descriptor, task, and "
        "resident-memory parent vector."
    ),
    "hierarchical_lease_rebind_preserves_owned_primary_and_physical": (
        "Moving a lease between optional client/request scopes preserves its owned, process, and "
        "physical quantities and changes only the enabled child charges."
    ),
    "hierarchical_lease_release_zeroes_every_level": (
        "Terminal release zeroes the owned, process, optional child, file-descriptor, task, and "
        "resident-memory parent charges."
    ),
    "hierarchical_lease_terminal_release_is_exactly_once": (
        "A released hierarchical lease rejects every later resize, rebind, and second release."
    ),
    "hierarchical_lease_pair_resize_is_atomic": (
        "The two dimensions of a live paired resize produce invariant next certificates together, "
        "with each dimension equal to its requested owned quantity."
    ),
}


def parse_proofs(text: str) -> list[Proof]:
    proofs: list[Proof] = []
    for match in PROOF_START.finditer(text):
        body_start = re.search(r"(?m)^\{", text[match.end() :])
        if body_start is None:
            raise ValueError(f"missing body for proof {match.group(1)}")
        opening = match.end() + body_start.start()
        depth = 0
        closing = -1
        for index in range(opening, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing < 0:
            raise ValueError(f"unterminated body for proof {match.group(1)}")
        proofs.append(
            Proof(
                name=match.group(1),
                line=text.count("\n", 0, match.start()) + 1,
                header=text[match.start() : opening],
                body=text[opening + 1 : closing].strip(),
            )
        )
    names = [proof.name for proof in proofs]
    duplicates = sorted(name for name, count in Counter(names).items() if count != 1)
    if duplicates:
        raise ValueError(f"duplicate proof function names: {', '.join(duplicates)}")
    return proofs


def component_for(proof: Proof) -> str:
    if proof.name in COMPONENT_OVERRIDES:
        return COMPONENT_OVERRIDES[proof.name]
    for start, end, component in COMPONENT_RANGES:
        if start <= proof.line <= end:
            return component
    raise ValueError(f"no component classification for source line {proof.line}")


def strategy_for(proof: Proof, component: str) -> str:
    if proof.name in CONCRETE_ORACLE_PROOFS:
        return "concrete_oracle"
    if proof.name in DEPENDENCY_CONSTANT_PROOFS:
        return "dependency_constants"
    if proof.name in COST_MODEL_PROOFS:
        return "cost_model"
    if proof.name in BITVECTOR_PROOFS or "bit_vector" in proof.body:
        return "bitvector"
    if proof.name in FINITE_DOMAIN_PROOFS:
        return "finite_domain"
    if proof.name in SEQUENCE_ALGEBRA_PROOFS:
        return "sequence_algebra"
    if proof.name in ARITHMETIC_GATE_PROOFS:
        return "arithmetic_gate"
    if proof.name in REFINED_INDUCTION_PROOFS:
        return "refined_induction"
    if re.search(rf"\b{re.escape(proof.name)}\s*\(", proof.body):
        if component == "HTTP/2 admission and lifecycle":
            return "h2_state_machine"
        return "induction"
    if component == "HTTP/2 admission and lifecycle":
        return "h2_state_machine"
    if component in STATE_MACHINE_COMPONENTS:
        return "state_machine"
    if component in FINITE_CASE_COMPONENTS or "match " in proof.body:
        return "finite_cases"
    return "definition"


def property_for(name: str) -> str:
    if name in PROPERTY_OVERRIDES:
        return PROPERTY_OVERRIDES[name]
    words = name.split("_")
    rendered = [ACRONYMS.get(word, word) for word in words]
    result = " ".join(rendered)
    if words[0] not in ACRONYMS:
        result = result[0].upper() + result[1:]
    return result + "."


def escape_cell(text: str) -> str:
    return text.replace("|", "&#124;").replace("\n", " ")


def render(proofs: list[Proof]) -> str:
    classified: list[tuple[Proof, str, str]] = []
    for proof in proofs:
        component = component_for(proof)
        classified.append((proof, component, strategy_for(proof, component)))

    strategy_counts = Counter(strategy for _, _, strategy in classified)
    rating_counts = Counter(STRATEGIES[strategy][2] for _, _, strategy in classified)
    empty = sum(not proof.body for proof, _, _ in classified)
    public = sum(
        bool(re.match(r"\s*pub\s+proof\s+fn", proof.header)) for proof, _, _ in classified
    )

    lines = [
        "# Verus proof strategies",
        "",
        "This page inventories every explicit `proof fn` in "
        "[`crates/verified/src/lib.rs`](../crates/verified/src/lib.rs). It names the component, "
        "states the claimed property in plain language, identifies the proof's real epistemic "
        "basis, and gives a deliberately skeptical review-confidence score.",
        "",
        "The unit of inventory is a named Verus theorem or lemma, not every function for which "
        "Verus generates a verification condition. Executable `fn` bodies prove implementation "
        "postconditions and `spec fn` bodies define models; listing those as if each were an "
        "independent security theorem would inflate the table and obscure the distinction. The "
        "higher-level composition claims, including executable PCRE2 grammar refinement, remain "
        "tracked in [`verification-status.json`](verification-status.json).",
        "",
        "## How to read the ratings",
        "",
        "The score is a maintainer judgment about how likely the *proof strategy and its current "
        "implementation* are to survive hostile review, not a Verus pass/fail result:",
        "",
        "| Score | Meaning |",
        "| ---: | --- |",
        "| 1–2 | Example-only, measured, or dependency-assumption evidence; useful but not a general proof of the production claim. |",
        "| 3–4 | The arithmetic or logical implication is sound, but the hard part is encoded as an assumed charge, limit, fact, or incomplete model. |",
        "| 5–6 | Exact finite model or case analysis with a material runtime-refinement or coverage seam. |",
        "| 7–8 | General invariant/induction or exact machine algebra with a credible executable refinement; external effects remain trusted. |",
        "| 9–10 | End-to-end refinement through all relevant production state and dependency semantics. No current row earns this. |",
        "",
        "A low score does **not** mean Verus failed to prove the stated formula. It means the formula "
        "may be easier than the security claim readers could infer from its name. In particular, "
        "an admission theorem of the form “if the gate accepted, the declared charge is below the "
        "declared limit” does not prove that the charge models actual resource use.",
        "",
        "## Inventory summary",
        "",
        f"The source currently contains **{len(proofs)}** explicit proof functions "
        f"(**{public} public**, **{len(proofs) - public} private lemmas**). "
        f"**{empty}** have empty proof bodies: SMT discharges them by unfolding definitions and "
        "using their preconditions. That is legitimate automation, but it is usually a shallow "
        "model-consistency result rather than an end-to-end implementation proof. The crate "
        "contains no accepted `assume`, `assume_specification`, or `external_body` escape hatch.",
        "",
        "| Proof basis | Rows | Default score |",
        "| --- | ---: | ---: |",
    ]
    for key, (title, _, rating) in STRATEGIES.items():
        count = strategy_counts.get(key, 0)
        if count:
            lines.append(f"| {title} | {count} | {rating}/10 |")
    lines.extend(
        [
            "",
            "| Score | Rows |",
            "| ---: | ---: |",
        ]
    )
    for rating in sorted(rating_counts):
        lines.append(f"| {rating}/10 | {rating_counts[rating]} |")

    lines.extend(
        [
            "",
            "## Strategy definitions",
            "",
            "| Basis | What the proof really rests on | Default score |",
            "| --- | --- | ---: |",
        ]
    )
    for title, description, rating in STRATEGIES.values():
        lines.append(f"| {title} | {escape_cell(description)} | {rating}/10 |")

    lines.extend(
        [
            "",
            "## Proof-by-proof inventory",
            "",
            "The property wording follows the theorem name; the linked source is authoritative for "
            "the exact `requires` and `ensures` clauses. Repeated component names are intentional.",
            "",
            "<!-- Generated by tests/proof_strategies.py; edit classifications there. -->",
            "| Component | Proof | Property claimed | Strategy / epistemic basis | Review confidence |",
            "| --- | --- | --- | --- | ---: |",
        ]
    )
    for proof, component, strategy in classified:
        title, description, rating = STRATEGIES[strategy]
        proof_link = (
            f"[`{proof.name}`](../crates/verified/src/lib.rs#L{proof.line})"
        )
        basis = f"**{title}.** {description}"
        lines.append(
            "| "
            + " | ".join(
                (
                    escape_cell(component),
                    proof_link,
                    escape_cell(property_for(proof.name)),
                    escape_cell(basis),
                    f"{rating}/10",
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## What this inventory does not prove",
            "",
            "The table is intentionally narrower than the overall assurance case. It does not turn "
            "a model-only theorem into evidence that all runtime paths call the gate, prove Rust "
            "RAII destruction as a Verus heap theorem, derive CPU or allocator worst cases from "
            "third-party source, model kernel scheduling/filesystem/network behavior, or establish "
            "Apache conformance. Those links are supplied, with varying strength, by executable "
            "refinement postconditions, source inventories, fuzzing, integration tests, measured "
            "budgets and explicit dependency/kernel assumptions.",
            "",
            "The most review-sensitive rows are therefore the score-2 dependency constants and "
            "concrete fnmatch oracles, followed by the score-3 regex cost model. A successful "
            "adversarial review should try to falsify those empirical/modeling premises before "
            "spending time rechecking the elementary SMT implications.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if docs/proof-strategies.md is absent or stale",
    )
    args = parser.parse_args()

    proofs = parse_proofs(SOURCE.read_text(encoding="utf-8"))
    expected = render(proofs)
    if args.check:
        actual = DOCUMENT.read_text(encoding="utf-8") if DOCUMENT.exists() else ""
        if actual != expected:
            print(
                "docs/proof-strategies.md is stale; run "
                "python3 tests/proof_strategies.py",
                file=sys.stderr,
            )
            return 1
        print(f"proof strategy inventory: {len(proofs)} explicit proof functions")
        return 0

    DOCUMENT.write_text(expected, encoding="utf-8")
    print(f"wrote {DOCUMENT.relative_to(ROOT)} with {len(proofs)} proof rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
