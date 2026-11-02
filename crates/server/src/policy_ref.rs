//! Pure reference evaluator for the security-relevant configuration phases.
//!
//! This module implements the same canonical order as the request dispatcher:
//!
//! ```text
//! Directory/access walk -> DirectoryMatch -> depth-interleaved Files -> Location -> If
//! ```
//!
//! It is intentionally kept free of I/O and `.htaccess` handling.  The live
//! dispatcher uses the same phase helpers, and the tests at the bottom compare
//! the reference result with `Config::effective_scope_req` for a generated
//! corpus.  The eventual Verus model should target this interface: a finite
//! scope, a finite rule list, and a request view.

use crate::config::{apply_deferred_req, apply_normal_rule_list, Config, Scope, ScopeRule, VHost};
use crate::http::Request;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

/// Evaluate configuration rules in canonical order without touching the
/// filesystem.  Conditional rules are collected and returned so a caller can
/// apply them with the request's environment.
pub fn effective_scope_req(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
) -> (Scope, Vec<ScopeRule>) {
    // No access-file layers.  The same verified phase plan is used for the
    // fast path, so the configuration-only and `.htaccess` paths cannot
    // diverge in phase order.
    let (scope, conditionals, _) =
        effective_scope_with_layers(cfg, vhost, fs_path, url_path, req, peer, &[]);
    (scope, conditionals)
}

/// A parsed per-directory access file, separated from filesystem I/O.
#[derive(Debug, Clone)]
pub struct AccessLayer {
    pub identity: crate::request_plan::LayerIdentity,
    pub scope: std::sync::Arc<Scope>,
    pub files: Vec<ScopeRule>,
    pub conditionals: Vec<ScopeRule>,
}

/// Evaluate the complete configuration/access-file interleaving.  Access
/// layers are supplied by the walker; this function is the single
/// implementation of the resulting merge order:
///
/// ```text
/// for each directory root..leaf:
///     Directory rules; access-file scope; defer config/access Files and If
/// DirectoryMatch
/// base config Files
/// for each directory root..leaf:
///     config Files; access-file Files
/// DirectoryMatch-nested Files
/// Location
/// config If; access If
/// ```
pub fn effective_scope_with_layers(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    layers: &[AccessLayer],
) -> (Scope, Vec<ScopeRule>, Vec<ScopeRule>) {
    let fname = fs_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    effective_scope_with_layers_and_file_name(
        cfg, vhost, fs_path, url_path, req, peer, layers, &fname,
    )
}

/// Evaluate the same canonical directory/access-file walk while supplying a
/// distinct basename to the Files phase.  Callers use this only to extract
/// lexical handler policy; authorization continues to use the canonical
/// evaluation above.
#[allow(clippy::too_many_arguments)]
pub fn effective_scope_with_layers_and_file_name(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    layers: &[AccessLayer],
    fname: &str,
) -> (Scope, Vec<ScopeRule>, Vec<ScopeRule>) {
    // This evaluator is also called directly by a few internal policy paths,
    // so retain the limit here even though RequestPlan normally rejects the
    // target first.  Fail closed instead of allocating an attacker-sized
    // ancestor vector.
    let start = if crate::files::is_dir_cached(fs_path) {
        fs_path
    } else {
        fs_path.parent().unwrap_or(fs_path)
    };
    let dirs = match crate::util::bounded_policy_ancestor_dirs(start) {
        Ok(dirs) => dirs,
        Err(_) => {
            let mut scope = vhost
                .map(|vhost| vhost.scope.clone())
                .unwrap_or_else(|| cfg.global.clone());
            scope.conditional_error = true;
            let _ = req.charge_policy_work(u64::MAX);
            return (scope, Vec::new(), Vec::new());
        }
    };
    let mut base_config_files = Vec::new();
    let mut config_locations = Vec::new();
    let mut config_conditionals = Vec::new();
    let mut scope = cfg.effective_scope_req_base_deferred_with_file_name(
        vhost,
        fs_path,
        url_path,
        req,
        peer,
        fname,
        &mut base_config_files,
        &mut config_locations,
        &mut config_conditionals,
    );
    let docroot = cfg.documentation_root_for(vhost);
    // Build the verified stage plan.  One `Walk` step consumes exactly one
    // directory in root-to-leaf order; `access` records whether that
    // directory has an `.htaccess` layer.  The remaining steps are the
    // deferred Files/Location/conditional suffix.
    let mut present = Vec::with_capacity(dirs.len());
    for dir in &dirs {
        present.push(layers.iter().any(|layer| layer.identity.dir == *dir));
    }
    let mut config_file_layers: Vec<Vec<ScopeRule>> = vec![Vec::new(); dirs.len()];
    let mut access_file_layers: Vec<Vec<ScopeRule>> = vec![Vec::new(); dirs.len()];
    let mut directory_match_files = Vec::new();
    let mut htaccess_conditionals = Vec::new();
    for step in crate::verified::access_plan_exec(&present) {
        match step {
            crate::verified::AccessStep::DirectoryConfig { depth } => {
                let dir = &dirs[depth];
                let mut dir_config_files = Vec::new();
                cfg.apply_directory_rules_for_dir(
                    vhost,
                    &mut scope,
                    req,
                    peer,
                    dir,
                    fs_path,
                    url_path,
                    &mut dir_config_files,
                    &mut config_locations,
                    &mut config_conditionals,
                );
                config_file_layers[depth] = dir_config_files;
            }
            crate::verified::AccessStep::DirectoryAccess { depth } => {
                let dir = &dirs[depth];
                let layer = layers
                    .iter()
                    .find(|layer| layer.identity.dir == *dir)
                    .expect("verified access step was derived from the same layer set");
                scope.merge(&layer.scope);
                access_file_layers[depth] = layer.files.clone();
                htaccess_conditionals.extend(layer.conditionals.iter().cloned());
            }
            crate::verified::AccessStep::DirectoryOwnPath => {
                // F61-C: the file's own path is the final walked entry of the
                // Directory phase; apply wildcard `<Directory>` sections that
                // match it before `<DirectoryMatch>`.
                cfg.apply_directory_own_path_rules(
                    vhost,
                    &mut scope,
                    Some(req),
                    fs_path,
                    url_path,
                    &mut directory_match_files,
                    &mut config_locations,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::DirectoryMatch => {
                cfg.apply_directory_match_rules(
                    vhost,
                    &mut scope,
                    Some(req),
                    fs_path,
                    url_path,
                    &mut directory_match_files,
                    &mut config_locations,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::BaseFiles => {
                apply_normal_rule_list(
                    &base_config_files,
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    fname,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::FilesConfig { depth } => {
                apply_normal_rule_list(
                    &config_file_layers[depth],
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    fname,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::FilesAccess { depth } => {
                apply_normal_rule_list(
                    &access_file_layers[depth],
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    fname,
                    &mut htaccess_conditionals,
                );
            }
            crate::verified::AccessStep::DirectoryMatchFiles => {
                apply_normal_rule_list(
                    &directory_match_files,
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    fname,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::ConfigLocation => {
                apply_normal_rule_list(
                    &config_locations,
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    fname,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::ConfigConditions
            | crate::verified::AccessStep::AccessConditions => {}
        }
    }
    config_conditionals.sort_by_key(|rule| rule.order);
    (scope, config_conditionals, htaccess_conditionals)
}

/// Apply the deferred conditional rules from `effective_scope_req`.
pub fn apply_conditionals(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    conditionals: &[ScopeRule],
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
) {
    let fname = fs_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let docroot = cfg.documentation_root_for(vhost);
    let mut chain_state = HashMap::new();
    apply_deferred_req(
        scope,
        conditionals,
        req,
        peer,
        &docroot,
        fs_path,
        url_path,
        &fname,
        &mut chain_state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::http::{Headers, Request, Version};
    use crate::verified::BodyFraming;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    fn request() -> Request {
        Request {
            method: "GET".into(),
            target: b"/secret.txt".to_vec(),
            raw_path: b"/secret.txt".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: BodyFraming::None,
        }
    }

    fn load(name: &str, text: &str) -> Config {
        let dir = PathBuf::from(std::env::temp_dir())
            .join(format!("vapache-policy-ref-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        fs::write(&path, format!("{}{text}", crate::config::TEST_CAPABILITIES)).unwrap();
        Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn signature(s: &Scope) -> String {
        format!(
            "requires={:?}|allow={:?}|methods={:?}|legacy={:?}|options={:?}|headers={:?}",
            s.authorization.requires,
            s.override_policy.raw_mode(),
            s.authorization.allow_methods,
            s.authorization.legacy,
            s.effective_options(),
            s.header_policy.set_headers
        )
    }

    fn compare(name: &str, text: &str) {
        let cfg = load(name, text);
        let req = request();
        let peer = "127.0.0.1".parse().unwrap();
        let fs_path = if name == "wildcard-directory" {
            Path::new("/srv/alice/public/secret.txt")
        } else {
            Path::new("/srv/secret.txt")
        };
        let (mut ref_scope, conditionals) =
            effective_scope_req(&cfg, None, fs_path, "/secret.txt", &req, peer);
        apply_conditionals(
            &cfg,
            None,
            &mut ref_scope,
            &conditionals,
            fs_path,
            "/secret.txt",
            &req,
            peer,
        );
        let live = cfg.effective_scope_req(None, fs_path, "/secret.txt", &req, peer);
        assert_eq!(signature(&ref_scope), signature(&live), "{name}");
        match name {
            "directory-files-location" => {
                assert!(
                    format!("{:?}", ref_scope.authorization.requires).contains("Local"),
                    "{name}"
                )
            }
            "conditional-last" | "files-glob" => assert!(
                format!("{:?}", ref_scope.authorization.requires).contains("AllDenied"),
                "{name}"
            ),
            "wildcard-directory" => {
                assert!(
                    format!("{:?}", ref_scope.authorization.requires).contains("Local"),
                    "{name}"
                )
            }
            _ => {}
        }
    }

    #[test]
    fn reference_matches_runtime_on_security_scope() {
        compare(
            "directory-files-location",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv>\n",
                "Require all granted\n",
                "</Directory>\n",
                "<Files \"secret.txt\">\n",
                "Require all denied\n",
                "</Files>\n",
                "<Location \"/secret.txt\">\n",
                "Require local\n",
                "</Location>\n",
            ),
        );
        compare(
            "conditional-last",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<If \"%{REQUEST_METHOD} == 'GET'\">\n",
                "Require all denied\n",
                "</If>\n",
                "<Directory /srv>\n",
                "Require all granted\n",
                "</Directory>\n",
            ),
        );
        compare(
            "wildcard-directory",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv/*/public>\n",
                "Require local\n",
                "</Directory>\n",
            ),
        );
        compare(
            "files-glob",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv>\n",
                "<Files \"secret*\">\n",
                "Require all denied\n",
                "</Files>\n",
                "</Directory>\n",
            ),
        );
        compare("baseline", "Listen 127.0.0.1:0\n");
    }

    #[test]
    fn verified_plan_pairs_one_walk_with_each_directory() {
        let present = [false, true, true];
        let plan = crate::verified::access_plan_exec(&present);
        assert_eq!(
            crate::verified::condition_source_plan_exec(),
            vec![
                crate::verified::ConditionSource::Config,
                crate::verified::ConditionSource::Access,
            ]
        );
        assert_eq!(plan.len(), present.len() * 2 + 2 * 2 + 7);
        assert_eq!(
            &plan[..5],
            &[
                crate::verified::AccessStep::DirectoryConfig { depth: 0 },
                crate::verified::AccessStep::DirectoryConfig { depth: 1 },
                crate::verified::AccessStep::DirectoryAccess { depth: 1 },
                crate::verified::AccessStep::DirectoryConfig { depth: 2 },
                crate::verified::AccessStep::DirectoryAccess { depth: 2 },
            ]
        );
        assert_eq!(
            &plan[5..8],
            &[
                crate::verified::AccessStep::DirectoryOwnPath,
                crate::verified::AccessStep::DirectoryMatch,
                crate::verified::AccessStep::BaseFiles,
            ]
        );
        assert_eq!(
            &plan[8..13],
            &[
                crate::verified::AccessStep::FilesConfig { depth: 0 },
                crate::verified::AccessStep::FilesConfig { depth: 1 },
                crate::verified::AccessStep::FilesAccess { depth: 1 },
                crate::verified::AccessStep::FilesConfig { depth: 2 },
                crate::verified::AccessStep::FilesAccess { depth: 2 },
            ]
        );
        assert_eq!(
            &plan[13..],
            &[
                crate::verified::AccessStep::DirectoryMatchFiles,
                crate::verified::AccessStep::ConfigLocation,
                crate::verified::AccessStep::ConfigConditions,
                crate::verified::AccessStep::AccessConditions,
            ]
        );
    }

    #[test]
    fn verified_plan_execution_is_stack_constant_for_deep_inputs() {
        // P29-A used roughly 18,000 ancestors to overflow a Tokio blocking
        // thread's stack.  Keep this above that reproducer and exercise both
        // verified iterative phase builders through the combined plan.
        let present = vec![false; 20_000];
        let plan = crate::verified::access_plan_exec(&present);
        assert_eq!(plan.len(), present.len() * 2 + 7);
        assert_eq!(
            plan.first(),
            Some(&crate::verified::AccessStep::DirectoryConfig { depth: 0 })
        );
        assert_eq!(
            plan.last(),
            Some(&crate::verified::AccessStep::AccessConditions)
        );
    }

    #[test]
    fn direct_policy_evaluation_rejects_deep_paths_fail_closed() {
        let cfg = load("p29-policy-path-bound", "Listen 127.0.0.1:0\n");
        let req = request();
        let mut path = PathBuf::from("/");
        for _ in 0..=crate::util::MAX_POLICY_PATH_COMPONENTS {
            path.push("x");
        }
        let (scope, conditionals) =
            effective_scope_req(&cfg, None, &path, "/x", &req, "127.0.0.1".parse().unwrap());
        assert!(scope.conditional_error);
        assert!(conditionals.is_empty());
        assert!(req.policy_budget_failed());
    }

    #[test]
    fn lexical_file_name_changes_handler_scope_without_replacing_canonical_access() {
        let cfg = load(
            "p13-lexical-handler",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv/secret>\n",
                "<Files \"run.cgi\">\n",
                "SetHandler cgi-script\n",
                "Require all denied\n",
                "</Files>\n",
                "</Directory>\n",
            ),
        );
        let req = request();
        let peer = "127.0.0.1".parse().unwrap();
        let canonical = Path::new("/srv/secret/run.cgi");
        let (canonical_scope, _, _) =
            effective_scope_with_layers(&cfg, None, canonical, "/public/link.txt", &req, peer, &[]);
        let (lexical_handler_scope, _, _) = effective_scope_with_layers_and_file_name(
            &cfg,
            None,
            canonical,
            "/public/link.txt",
            &req,
            peer,
            &[],
            "link.txt",
        );
        assert_eq!(
            crate::config::effective_handler(&canonical_scope, b"link.txt"),
            Some("cgi-script")
        );
        assert!(format!("{:?}", canonical_scope.authorization.requires).contains("AllDenied"));
        assert_eq!(
            crate::config::effective_handler(&lexical_handler_scope, b"link.txt"),
            None
        );
    }
}
