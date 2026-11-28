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
    (1, 100, "Configuration and cache generations"),
    (101, 247, "Backend endpoint identity"),
    (248, 665, "URI path canonicalization"),
    (666, 850, "Percent encoding"),
    (851, 1100, "Authority parsing"),
    (1101, 1700, "Rewrite target and sink classification"),
    (1701, 1940, "Authorized plan and FastCGI identity"),
    (1941, 2200, "Transform capability and terminal sink admission"),
    (2201, 2280, "Descriptor and inode stability"),
    (2281, 2438, "Rewrite query, restart, map and backreference policy"),
    (2439, 2667, "PCRE2 positive grammar"),
    (2668, 3218, "PCRE2 semantic AST and nginx regex bridge"),
    (3219, 3333, "Cache invalidation and disk identity"),
    (3334, 3439, "Configured input-size gates"),
    (3440, 3589, "Request resource admission"),
    (3590, 3799, "MultiViews admission and authorization"),
    (3800, 3949, "Access-program and regex work accounting"),
    (3950, 4189, "Rewrite filesystem containment"),
    (4190, 4363, "Expression and path matching"),
    (4364, 4469, "Shared memory, maps and queues"),
    (4470, 4724, "Dependency and TLS call boundaries"),
    (4725, 4769, "Generic resource-budget admission"),
    (4770, 4849, "Cancellation boundaries"),
    (4850, 5079, "Hierarchical resource accounting"),
    (5080, 5339, "Worker and output ownership"),
    (5340, 5489, "Request body phase machine"),
    (5490, 5889, "Dynamic outcome lifecycle"),
    (5890, 6489, "Internal requests, redirects and recovery"),
    (6490, 6589, "Body, retry and expression-file admission"),
    (6590, 6979, "Rewrite rule transitions"),
    (6980, 7729, "Rewrite program machine"),
    (7730, 7831, "Access-file selection"),
    (7832, 7929, "Policy-bit meet"),
    (7930, 8039, "Options, handler and authorization configuration"),
    (8040, 8139, "Authentication identity and cache"),
    (8140, 8219, "Authorization providers and override categories"),
    (8220, 8379, ".htaccess admission"),
    (8380, 9039, "Cache-key and lookup identity"),
    (9040, 9201, "Header and token syntax"),
    (9202, 9589, "HTTP/1 framing and byte ranges"),
    (9590, 10299, "Proxy request serialization"),
    (10300, 10839, "Header and range parsing"),
    (10840, 11451, "CGI and mapping bounds"),
    (11452, 11749, "Compression resource policy"),
    (11750, 11779, "Client quota identity"),
    (11780, 11859, "Service and process identity"),
    (11860, 12004, "CGI/backend response admission"),
    (12005, 12289, "CGI environment and regex admission"),
    (12290, 12535, "Cache lookup and expression authorization"),
    (12536, 12727, "Proxy identity and authorization algebra"),
    (12728, 13254, "Configuration phase ordering"),
    (13255, 14367, "Whole request-policy state machine"),
    (14368, 15012, "Configuration merge helpers"),
    (15013, 15341, "RemoteIP and virtual-host identity"),
    (15342, 16588, "Configuration front-end refinement"),
    (16589, 16776, "Container-field merge"),
    (16777, 19766, "HTTP/2 admission and lifecycle"),
    (19767, 20019, "Access/cache prefilters and mapping order"),
    (20020, 20655, "fnmatch semantics"),
    (20656, 20825, "Handler and CGI capability admission"),
    (20826, 20951, "Authentication-file and FastCGI path immutability"),
    (20952, 21425, "Nginx lexer and parser refinement"),
    (21426, 21704, "Nginx route-index refinement"),
    (21705, 21832, "Nginx lowering closure"),
    (21833, 22010, "Nginx transformation language"),
    (22011, 22220, "Source-neutral scope merge"),
    (22221, 22375, "Common-IR request refinement"),
)


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
    "Request body phase machine",
    "Dynamic outcome lifecycle",
    "Rewrite rule transitions",
    "Rewrite program machine",
    "Whole request-policy state machine",
    "Nginx lexer and parser refinement",
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


def component_for(line: int) -> str:
    for start, end, component in COMPONENT_RANGES:
        if start <= line <= end:
            return component
    raise ValueError(f"no component classification for source line {line}")


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
        component = component_for(proof.line)
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
