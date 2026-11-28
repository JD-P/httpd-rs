//! Source-neutral configuration IR shared by the Apache and nginx frontends.
//!
//! The runtime deliberately does not expose a generic module or scripting
//! interface.  Frontends may emit only the finite route and value operations
//! in this module; everything else is rejected while loading configuration.

use crate::apache_regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const MAX_ROUTES_PER_SERVER: usize = 512;
pub const MAX_NGINX_ROUTES: usize = 8_192;
pub const MAX_NGINX_DERIVED_POLICY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_NGINX_SERVERS: usize = 1024;
pub const MAX_SERVER_NAMES: usize = 4096;
pub const MAX_SERVER_NAME_BYTES: usize = 256 * 1024;
pub const MAX_NGINX_AUTHORITY_NAME_BYTES: usize = 253;
pub const MAX_VALUE_SEGMENTS: usize = 32;
pub const MAX_TRANSFORMS_PER_SCOPE: usize = 128;
pub const MAX_TRANSFORM_VALUE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Apache,
    Nginx,
}

/// A compiled, source-neutral configuration before process-wide derived
/// indexes and conservative feature bits are finalized.  Apache and nginx
/// both produce this value; only their route-selection programs differ.
#[derive(Debug, Clone)]
pub struct ConfigIr {
    pub(crate) config: crate::config::Config,
    pub(crate) routes: RouteProgram<crate::config::Scope>,
}

impl ConfigIr {
    pub(crate) fn apache(config: crate::config::Config) -> Result<Self, String> {
        let source = httpd_rs_verified::ConfigIrSource::Apache;
        if !config_scope_program_is_refined(&config, source) {
            return Err("Apache frontend emitted a Scope outside the verified merge fold".into());
        }
        Ok(Self {
            config,
            routes: RouteProgram::Apache,
        })
    }

    pub(crate) fn nginx(
        config: crate::config::Config,
        servers: Vec<Vec<Route<crate::config::Scope>>>,
    ) -> Result<Self, String> {
        let source = httpd_rs_verified::ConfigIrSource::Nginx;
        if !config_scope_program_is_refined(&config, source)
            || !servers.iter().flatten().all(|route| {
                route.policy.merge_refined_for(source) && route.policy.merge_source() == source
            })
        {
            return Err("nginx frontend emitted a Scope outside the verified merge fold".into());
        }
        let server_names = config
            .vhosts
            .iter()
            .map(|vhost| {
                vhost
                    .server_name
                    .iter()
                    .chain(vhost.aliases.iter())
                    .cloned()
                    .collect()
            })
            .collect();
        Ok(Self {
            config,
            routes: RouteProgram::nginx(servers, server_names)?,
        })
    }
}

fn scope_rule_is_refined(
    rule: &crate::config::ScopeRule,
    source: httpd_rs_verified::ConfigIrSource,
) -> bool {
    rule.delta.merge_refined_for(source)
        && rule.delta.merge_source() == source
        && rule
            .nested
            .iter()
            .all(|nested| scope_rule_is_refined(nested, source))
}

fn proxy_container_is_refined(
    container: &crate::config::ProxyContainer,
    source: httpd_rs_verified::ConfigIrSource,
) -> bool {
    container.delta.merge_refined_for(source)
        && container.delta.merge_source() == source
        && container
            .rules
            .iter()
            .all(|rule| scope_rule_is_refined(rule, source))
}

/// Publication-time refinement gate shared by both configuration frontends.
/// Every policy-bearing Scope, including nested conditionals and proxy
/// containers, must carry the frontend's source tag and a valid certificate
/// from the same immutable component fold before it can become ConfigIr.
fn config_scope_program_is_refined(
    config: &crate::config::Config,
    source: httpd_rs_verified::ConfigIrSource,
) -> bool {
    config.global.merge_refined_for(source)
        && config.global.merge_source() == source
        && config
            .global_rules
            .iter()
            .all(|rule| scope_rule_is_refined(rule, source))
        && config
            .proxy_containers
            .iter()
            .all(|container| proxy_container_is_refined(container, source))
        && config.vhosts.iter().all(|vhost| {
            vhost.scope.merge_refined_for(source)
                && vhost.scope.merge_source() == source
                && vhost.delta.merge_refined_for(source)
                && vhost.delta.merge_source() == source
                && vhost
                    .rules
                    .iter()
                    .all(|rule| scope_rule_is_refined(rule, source))
                && vhost
                    .proxy_containers
                    .iter()
                    .all(|container| proxy_container_is_refined(container, source))
        })
}

impl ConfigFormat {
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("apache") || value.eq_ignore_ascii_case("apache2") {
            Some(Self::Apache)
        } else if value.eq_ignore_ascii_case("nginx") {
            Some(Self::Nginx)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub enum RouteMatcher {
    Exact(String),
    Prefix { value: String, suppress_regex: bool },
    Regex { value: String, regex: Regex },
}

#[derive(Debug, Clone)]
pub struct Route<T> {
    pub matcher: RouteMatcher,
    pub policy: T,
    pub declaration_order: usize,
}

#[derive(Debug, Clone)]
pub enum RouteProgram<T> {
    Apache,
    Nginx {
        servers: Vec<Vec<Route<T>>>,
        route_indexes: Vec<NginxRouteIndex>,
        server_names: NginxServerNameTable,
    },
}

/// Precomputed literal indexes for nginx's request-time location winner
/// machine. Regexes remain in declaration order because that order is part of
/// nginx semantics; exact locations do not need a linear scan and literal
/// prefixes are visited longest-first.
#[derive(Debug, Clone)]
pub struct NginxRouteIndex {
    exact: HashMap<String, usize>,
    prefixes: Vec<usize>,
    regexes: Vec<usize>,
    matcher_bytes: u64,
    certified: bool,
}

impl NginxRouteIndex {
    fn build<T>(routes: &[Route<T>]) -> Result<Self, String> {
        let mut exact = HashMap::new();
        let mut exact_routes = Vec::new();
        let mut prefixes = Vec::new();
        let mut regexes = Vec::new();
        let mut matcher_bytes = 0u64;
        for (index, route) in routes.iter().enumerate() {
            let width = match &route.matcher {
                RouteMatcher::Exact(value)
                | RouteMatcher::Prefix { value, .. }
                | RouteMatcher::Regex { value, .. } => value.len(),
            };
            matcher_bytes = matcher_bytes.saturating_add(width as u64);
            match &route.matcher {
                RouteMatcher::Exact(value) => {
                    exact_routes.push(index);
                    let replace = exact.get(value).is_none_or(|current: &usize| {
                        route.declaration_order < routes[*current].declaration_order
                    });
                    if replace {
                        exact.insert(value.clone(), index);
                    }
                }
                RouteMatcher::Prefix { .. } => prefixes.push(index),
                RouteMatcher::Regex { .. } => regexes.push(index),
            }
        }
        prefixes.sort_by_key(|index| {
            let RouteMatcher::Prefix { value, .. } = &routes[*index].matcher else {
                unreachable!("prefix index contains only prefix locations")
            };
            (
                std::cmp::Reverse(value.len()),
                routes[*index].declaration_order,
            )
        });
        regexes.sort_by_key(|index| routes[*index].declaration_order);

        // Certify the derived index before it can become request-reachable.
        // `exact` deliberately coalesces duplicate strings for lookup, while
        // `exact_routes` retains every source route for the partition proof.
        let mut seen = vec![false; routes.len()];
        let mut unique_and_complete = true;
        let mut declaration_orders = HashSet::with_capacity(routes.len());
        for index in exact_routes
            .iter()
            .chain(prefixes.iter())
            .chain(regexes.iter())
        {
            if *index >= seen.len() || seen[*index] {
                unique_and_complete = false;
                break;
            }
            seen[*index] = true;
        }
        unique_and_complete &= seen.iter().all(|seen| *seen);
        unique_and_complete &= routes
            .iter()
            .all(|route| declaration_orders.insert(route.declaration_order));
        let prefix_sorted = prefixes.windows(2).all(|pair| {
            let RouteMatcher::Prefix {
                value: previous, ..
            } = &routes[pair[0]].matcher
            else {
                return false;
            };
            let RouteMatcher::Prefix { value: next, .. } = &routes[pair[1]].matcher else {
                return false;
            };
            httpd_rs_verified::nginx_prefix_index_pair_admit(
                previous.len() as u64,
                routes[pair[0]].declaration_order as u64,
                next.len() as u64,
                routes[pair[1]].declaration_order as u64,
            )
        });
        let regex_sorted = regexes.windows(2).all(|pair| {
            httpd_rs_verified::nginx_regex_index_pair_admit(
                routes[pair[0]].declaration_order as u64,
                routes[pair[1]].declaration_order as u64,
            )
        });
        let certified = httpd_rs_verified::nginx_index_partition_admit(
            routes.len() as u64,
            exact_routes.len() as u64,
            prefixes.len() as u64,
            regexes.len() as u64,
            unique_and_complete,
            prefix_sorted,
            regex_sorted,
        );
        if !certified {
            return Err("nginx route index failed its refinement certificate".into());
        }
        Ok(Self {
            exact,
            prefixes,
            regexes,
            matcher_bytes,
            certified,
        })
    }

    fn select<'a, T>(&self, routes: &'a [Route<T>], path: &str) -> Option<&'a Route<T>> {
        if !self.certified {
            return None;
        }
        let exact = self.exact.get(path).and_then(|index| routes.get(*index));
        if exact.is_some() {
            return exact;
        }
        let prefix = self.prefixes.iter().find_map(|index| {
            let route = routes.get(*index)?;
            let RouteMatcher::Prefix { value, .. } = &route.matcher else {
                return None;
            };
            path.starts_with(value).then_some(route)
        });
        if prefix.is_some_and(|route| {
            matches!(
                route.matcher,
                RouteMatcher::Prefix {
                    suppress_regex: true,
                    ..
                }
            )
        }) {
            return prefix;
        }
        let regex_match = self.regexes.iter().find_map(|index| {
            let route = routes.get(*index)?;
            let RouteMatcher::Regex { regex, .. } = &route.matcher else {
                return None;
            };
            regex.is_nginx_match(path).then_some(route)
        });
        select_accumulated_route(exact, prefix, regex_match)
    }
}

/// One compiled nginx server-name program is shared by HTTP Host routing and
/// TLS SNI certificate selection. This prevents the transport identity from
/// applying a subtly different wildcard or tie-breaking policy.
#[derive(Debug, Clone)]
pub struct NginxServerNameTable {
    #[allow(dead_code)]
    source_names: Vec<Vec<String>>,
    exact: HashMap<String, Vec<usize>>,
    leading: HashMap<String, Vec<usize>>,
    trailing: HashMap<String, Vec<usize>>,
}

fn first_sorted_intersection(left: &[usize], right: &[usize]) -> Option<usize> {
    debug_assert!(left.windows(2).all(|pair| pair[0] < pair[1]));
    debug_assert!(right.windows(2).all(|pair| pair[0] < pair[1]));
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => return Some(left[left_index]),
        }
    }
    None
}

impl NginxServerNameTable {
    pub(crate) fn new(server_names: Vec<Vec<String>>) -> Result<Self, String> {
        if server_names.len() > MAX_NGINX_SERVERS {
            return Err(format!(
                "nginx configuration exceeds the {MAX_NGINX_SERVERS}-server bound"
            ));
        }
        let count = server_names.iter().map(Vec::len).sum::<usize>();
        let bytes = server_names
            .iter()
            .flatten()
            .map(String::len)
            .sum::<usize>();
        if count > MAX_SERVER_NAMES || bytes > MAX_SERVER_NAME_BYTES {
            return Err(format!(
                "nginx server names exceed the {MAX_SERVER_NAMES}-name/{MAX_SERVER_NAME_BYTES}-byte bound"
            ));
        }
        let source_names = server_names.clone();
        let mut exact: HashMap<String, Vec<usize>> = HashMap::new();
        let mut leading: HashMap<String, Vec<usize>> = HashMap::new();
        let mut trailing: HashMap<String, Vec<usize>> = HashMap::new();
        for (server, raw_names) in server_names.into_iter().enumerate() {
            for raw in raw_names {
                let name = normalize_nginx_authority(&raw);
                if let Some(suffix) = name.strip_prefix('*') {
                    let matches = leading.entry(suffix.to_string()).or_default();
                    if matches.last() != Some(&server) {
                        matches.push(server);
                    }
                } else if let Some(prefix) = name.strip_suffix('*') {
                    let matches = trailing.entry(prefix.to_string()).or_default();
                    if matches.last() != Some(&server) {
                        matches.push(server);
                    }
                } else {
                    let matches = exact.entry(name).or_default();
                    if matches.last() != Some(&server) {
                        matches.push(server);
                    }
                }
            }
        }
        Ok(Self {
            source_names,
            exact,
            leading,
            trailing,
        })
    }

    pub(crate) fn select(&self, candidates: &[usize], host: Option<&str>) -> Option<usize> {
        let default = *candidates.first()?;
        let Some(host) = host else {
            return Some(default);
        };
        let bare = normalize_nginx_authority(host);
        // Configured names are bounded to the DNS presentation ceiling. A
        // longer RFC 3986 reg-name cannot equal one and admitting it to the
        // suffix probes would make a dot-heavy Host perform quadratic hash
        // work. Treat it as an unmatched name and retain the listener's
        // deterministic default server.
        if bare.len() > MAX_NGINX_AUTHORITY_NAME_BYTES {
            return Some(default);
        }
        let exact_server = self
            .exact
            .get(&bare)
            .and_then(|exact| first_sorted_intersection(candidates, exact));
        // A supported leading wildcard is always `*.suffix`, so every
        // possible match begins at a dot in the normalized authority. Walk
        // left-to-right to query the longest suffix first. Trailing `prefix.*`
        // candidates are the mirror image and are queried longest-first.
        let leading_server = bare.match_indices('.').find_map(|(index, _)| {
            self.leading
                .get(&bare[index..])
                .and_then(|matches| first_sorted_intersection(candidates, matches))
        });
        let trailing_server = bare.rmatch_indices('.').find_map(|(index, _)| {
            self.trailing
                .get(&bare[..=index])
                .and_then(|matches| first_sorted_intersection(candidates, matches))
        });
        match httpd_rs_verified::nginx_server_name_winner_class(
            exact_server.is_some(),
            leading_server.is_some(),
            trailing_server.is_some(),
        ) {
            1 => exact_server,
            2 => leading_server,
            3 => trailing_server,
            _ => Some(default),
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn select_reference(&self, candidates: &[usize], host: Option<&str>) -> Option<usize> {
        let default = *candidates.first()?;
        let Some(host) = host else {
            return Some(default);
        };
        let bare = normalize_nginx_authority(host);
        if bare.len() > MAX_NGINX_AUTHORITY_NAME_BYTES {
            return Some(default);
        }
        for &index in candidates {
            if self.source_names.get(index).is_some_and(|names| {
                names
                    .iter()
                    .any(|name| !name.contains('*') && normalize_nginx_authority(name) == bare)
            }) {
                return Some(index);
            }
        }
        let mut leading: Option<(usize, usize, usize)> = None;
        let mut trailing: Option<(usize, usize, usize)> = None;
        for (rank, &index) in candidates.iter().enumerate() {
            let Some(names) = self.source_names.get(index) else {
                continue;
            };
            for name in names {
                let name = normalize_nginx_authority(name);
                if let Some(suffix) = name.strip_prefix('*') {
                    if bare.len() > suffix.len()
                        && bare.ends_with(suffix)
                        && leading.is_none_or(|(_, width, current_rank)| {
                            suffix.len() > width || (suffix.len() == width && rank < current_rank)
                        })
                    {
                        leading = Some((index, suffix.len(), rank));
                    }
                } else if let Some(prefix) = name.strip_suffix('*') {
                    if bare.len() > prefix.len()
                        && bare.starts_with(prefix)
                        && trailing.is_none_or(|(_, width, current_rank)| {
                            prefix.len() > width || (prefix.len() == width && rank < current_rank)
                        })
                    {
                        trailing = Some((index, prefix.len(), rank));
                    }
                }
            }
        }
        leading
            .or(trailing)
            .map(|(index, _, _)| index)
            .or(Some(default))
    }
}

pub(crate) fn normalize_nginx_authority(authority: &str) -> String {
    let authority = authority.trim();
    let bare = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map(|(value, _)| value).unwrap_or(rest)
    } else if authority
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b':')
        .count()
        == 1
    {
        authority
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(authority)
    } else {
        authority
    };
    bare.trim_end_matches('.').to_ascii_lowercase()
}

impl<T> Default for RouteProgram<T> {
    fn default() -> Self {
        Self::Apache
    }
}

impl<T> RouteProgram<T> {
    pub fn nginx(
        servers: Vec<Vec<Route<T>>>,
        server_names: Vec<Vec<String>>,
    ) -> Result<Self, String> {
        if servers.len() != server_names.len() {
            return Err("nginx server route/name cardinality mismatch".into());
        }
        if servers
            .iter()
            .any(|routes| routes.len() > MAX_ROUTES_PER_SERVER)
        {
            return Err(format!(
                "nginx server exceeds the {MAX_ROUTES_PER_SERVER}-location bound"
            ));
        }
        let total_routes = servers
            .iter()
            .try_fold(0usize, |total, routes| total.checked_add(routes.len()));
        if total_routes.is_none_or(|total| total > MAX_NGINX_ROUTES) {
            return Err(format!(
                "nginx configuration exceeds the {MAX_NGINX_ROUTES}-location aggregate bound"
            ));
        }
        if servers.len() > MAX_NGINX_SERVERS {
            return Err(format!(
                "nginx configuration exceeds the {MAX_NGINX_SERVERS}-server bound"
            ));
        }
        let route_indexes = servers
            .iter()
            .map(|routes| NginxRouteIndex::build(routes))
            .collect::<Result<Vec<_>, _>>()?;
        let server_names = NginxServerNameTable::new(server_names)?;
        Ok(Self::Nginx {
            servers,
            route_indexes,
            server_names,
        })
    }

    pub fn is_nginx(&self) -> bool {
        matches!(self, Self::Nginx { .. })
    }

    pub(crate) fn source_kind(&self) -> httpd_rs_verified::ConfigIrSource {
        match self {
            Self::Apache => httpd_rs_verified::ConfigIrSource::Apache,
            Self::Nginx { .. } => httpd_rs_verified::ConfigIrSource::Nginx,
        }
    }

    /// Construction is the proof boundary: nginx programs contain only
    /// indexes accepted by the verified partition/order checker. Apache uses
    /// its existing linear rule program and is refined by construction.
    pub(crate) fn is_refined(&self) -> bool {
        match self {
            Self::Apache => true,
            Self::Nginx { route_indexes, .. } => route_indexes.iter().all(|index| index.certified),
        }
    }

    pub fn select(&self, server: usize, path: &str) -> Option<&T> {
        self.select_with_identity(server, path)
            .map(|(policy, _)| policy)
    }

    /// Select one nginx route together with its source declaration identity.
    /// Keeping these in one return value prevents request-plan construction
    /// from recomputing (and potentially disagreeing about) the winning
    /// location after its policy has supplied the mapping root.
    pub(crate) fn select_with_identity(&self, server: usize, path: &str) -> Option<(&T, usize)> {
        let Self::Nginx {
            servers,
            route_indexes,
            ..
        } = self
        else {
            return None;
        };
        route_indexes
            .get(server)?
            .select(servers.get(server)?, path)
            .map(|route| (&route.policy, route.declaration_order))
    }

    pub fn policies(&self) -> impl Iterator<Item = &T> {
        let routes: &[Vec<Route<T>>] = match self {
            Self::Apache => &[],
            Self::Nginx { servers, .. } => servers,
        };
        routes
            .iter()
            .flat_map(|server| server.iter().map(|route| &route.policy))
    }

    pub fn select_metered(
        &self,
        server: usize,
        path: &str,
        req: &crate::http::Request,
    ) -> Result<Option<&T>, &'static str> {
        let Self::Nginx {
            servers,
            route_indexes,
            ..
        } = self
        else {
            return Ok(None);
        };
        let Some(routes) = servers.get(server) else {
            return Ok(None);
        };
        let Some(index) = route_indexes.get(server) else {
            return Ok(None);
        };
        let work = httpd_rs_verified::nginx_route_selection_work(
            routes.len() as u64,
            index.matcher_bytes,
            path.len() as u64,
        )
        .unwrap_or(u64::MAX);
        req.charge_policy_work(work)?;
        Ok(index.select(routes, path).map(|route| &route.policy))
    }

    /// Select an nginx virtual server from the address-bucket candidates.
    /// Exact names win, followed by the longest leading-wildcard suffix, then
    /// the longest trailing-wildcard prefix. Regex server names are rejected
    /// by the frontend, so the first candidate is the address default.
    pub fn select_nginx_server(&self, candidates: &[usize], host: Option<&str>) -> Option<usize> {
        let Self::Nginx { server_names, .. } = self else {
            return None;
        };
        server_names.select(candidates, host)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn assert_nginx_refinement(&self, paths: &[&str], hosts: &[&str]) {
        let Self::Nginx {
            servers,
            route_indexes,
            server_names,
        } = self
        else {
            return;
        };
        for (server, routes) in servers.iter().enumerate() {
            for path in paths {
                let indexed = route_indexes[server]
                    .select(routes, path)
                    .map(|route| route.declaration_order);
                let reference =
                    select_nginx_route(routes, path).map(|route| route.declaration_order);
                assert_eq!(indexed, reference, "nginx route-index refinement failed");
            }
        }
        let candidates: Vec<usize> = (0..servers.len()).collect();
        for host in hosts {
            assert_eq!(
                server_names.select(&candidates, Some(host)),
                server_names.select_reference(&candidates, Some(host)),
                "nginx server-name index refinement failed"
            );
        }
    }
}

/// nginx HTTP location selection: exact first; remember the longest literal
/// prefix; a `^~` prefix suppresses regex evaluation; otherwise the first
/// matching regex in declaration order wins; finally use the longest prefix.
pub fn select_nginx_route<'a, T>(routes: &'a [Route<T>], path: &str) -> Option<&'a Route<T>> {
    let mut state = httpd_rs_verified::nginx_route_accumulator_empty();
    let mut exact = None;
    let mut prefix = None;
    let mut regex = None;
    for route in routes {
        let next = match &route.matcher {
            RouteMatcher::Exact(value) => httpd_rs_verified::nginx_route_accumulate(
                state,
                httpd_rs_verified::NginxRouteCandidateKind::Exact,
                value == path,
                value.len() as u64,
                route.declaration_order as u64,
                false,
            ),
            RouteMatcher::Prefix {
                value,
                suppress_regex,
            } => httpd_rs_verified::nginx_route_accumulate(
                state,
                httpd_rs_verified::NginxRouteCandidateKind::Prefix,
                path.starts_with(value),
                value.len() as u64,
                route.declaration_order as u64,
                *suppress_regex,
            ),
            RouteMatcher::Regex { value, regex } => httpd_rs_verified::nginx_route_accumulate(
                state,
                httpd_rs_verified::NginxRouteCandidateKind::Regex,
                regex.is_nginx_match(path),
                value.len() as u64,
                route.declaration_order as u64,
                false,
            ),
        };
        if next.exact != state.exact || next.exact_order != state.exact_order {
            exact = Some(route);
        }
        if next.prefix != state.prefix
            || next.prefix_width != state.prefix_width
            || next.prefix_order != state.prefix_order
        {
            prefix = Some(route);
        }
        if next.regex != state.regex || next.regex_order != state.regex_order {
            regex = Some(route);
        }
        state = next;
    }
    select_accumulated_route(exact, prefix, regex)
}

fn select_accumulated_route<'a, T>(
    exact: Option<&'a Route<T>>,
    prefix: Option<&'a Route<T>>,
    regex: Option<&'a Route<T>>,
) -> Option<&'a Route<T>> {
    let mut state = httpd_rs_verified::nginx_route_accumulator_empty();
    for (kind, route) in [
        (httpd_rs_verified::NginxRouteCandidateKind::Exact, exact),
        (httpd_rs_verified::NginxRouteCandidateKind::Prefix, prefix),
        (httpd_rs_verified::NginxRouteCandidateKind::Regex, regex),
    ] {
        let Some(route) = route else { continue };
        let (width, suppresses_regex) = match &route.matcher {
            RouteMatcher::Prefix {
                value,
                suppress_regex,
            } => (value.len(), *suppress_regex),
            RouteMatcher::Exact(value) | RouteMatcher::Regex { value, .. } => (value.len(), false),
        };
        state = httpd_rs_verified::nginx_route_accumulate(
            state,
            kind,
            true,
            width as u64,
            route.declaration_order as u64,
            suppresses_regex,
        );
    }
    let winner = httpd_rs_verified::nginx_route_accumulator_winner(state);
    match winner.class {
        1 => exact,
        2 | 4 => prefix,
        3 => regex,
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueVariable {
    Host,
    HttpHost,
    RemoteAddr,
    ProxyAddXForwardedFor,
    ProxyHost,
    Scheme,
    HttpUpgrade,
    ConnectionUpgrade,
    ServerPort,
    ServerName,
    RequestUri,
    Uri,
    DocumentUri,
    RequestMethod,
    QueryString,
    ContentType,
    ContentLength,
    DocumentRoot,
    RealPathRoot,
    FastCgiScriptName,
    FastCgiPathInfo,
    RequestFilename,
    ServerProtocol,
    Https,
    RemotePort,
    ServerAddr,
    GatewayInterface,
    ServerSoftware,
    HttpHeader(String),
    Cookie(String),
    Argument(String),
}

impl ValueVariable {
    fn provenance(&self) -> httpd_rs_verified::TransformValueClass {
        use httpd_rs_verified::TransformValueClass as Class;
        match self {
            // `$http_host` is the exact wire spelling, but both H1 and H2
            // adapters validate it as an HTTP authority before constructing
            // Request. It may therefore retain spelling/port while sharing
            // the authority provenance class with the normalized `$host`.
            Self::Host | Self::HttpHost | Self::ProxyHost | Self::ServerName => {
                Class::CanonicalAuthority
            }
            Self::RemoteAddr | Self::ProxyAddXForwardedFor => Class::TrustedPeer,
            Self::DocumentRoot
            | Self::RealPathRoot
            | Self::FastCgiScriptName
            | Self::RequestFilename => Class::AuthorizedPath,
            Self::Scheme
            | Self::ConnectionUpgrade
            | Self::ServerPort
            | Self::RequestMethod
            | Self::ServerProtocol
            | Self::Https
            | Self::RemotePort
            | Self::ServerAddr
            | Self::GatewayInterface
            | Self::ServerSoftware => Class::ProtocolMetadata,
            Self::HttpHeader(name) if name.eq_ignore_ascii_case("x-forwarded-for") => {
                Class::ClientForwardedFor
            }
            Self::HttpUpgrade
            | Self::RequestUri
            | Self::Uri
            | Self::DocumentUri
            | Self::QueryString
            | Self::ContentType
            | Self::ContentLength
            | Self::FastCgiPathInfo
            | Self::HttpHeader(_)
            | Self::Cookie(_)
            | Self::Argument(_) => Class::RequestBytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSegment {
    Literal(Vec<u8>),
    Variable(ValueVariable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueExpr {
    segments: Vec<ValueSegment>,
}

impl ValueExpr {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.as_bytes().contains(&0) {
            return Err("NUL is not permitted in a transformation value".into());
        }
        if value.len() > MAX_TRANSFORM_VALUE_BYTES {
            return Err(format!(
                "transformation value exceeds {MAX_TRANSFORM_VALUE_BYTES} bytes"
            ));
        }
        let bytes = value.as_bytes();
        let mut segments = Vec::new();
        let mut literal = Vec::new();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'$') {
                literal.push(b'$');
                index += 2;
                continue;
            }
            if bytes[index] != b'$' {
                literal.push(bytes[index]);
                index += 1;
                continue;
            }
            if !literal.is_empty() {
                segments.push(ValueSegment::Literal(std::mem::take(&mut literal)));
            }
            let (name, next) = if bytes.get(index + 1) == Some(&b'{') {
                let end = bytes[index + 2..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|offset| index + 2 + offset)
                    .ok_or_else(|| "unterminated ${...} transformation variable".to_string())?;
                (&value[index + 2..end], end + 1)
            } else {
                let mut end = index + 1;
                while bytes
                    .get(end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    end += 1;
                }
                if end == index + 1 {
                    return Err("bare '$' in transformation value".into());
                }
                (&value[index + 1..end], end)
            };
            segments.push(ValueSegment::Variable(parse_variable(name)?));
            index = next;
            if segments.len() > MAX_VALUE_SEGMENTS {
                return Err(format!(
                    "transformation contains more than {MAX_VALUE_SEGMENTS} segments"
                ));
            }
        }
        if !literal.is_empty() || segments.is_empty() {
            segments.push(ValueSegment::Literal(literal));
        }
        if segments.len() > MAX_VALUE_SEGMENTS {
            return Err(format!(
                "transformation contains more than {MAX_VALUE_SEGMENTS} segments"
            ));
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[ValueSegment] {
        &self.segments
    }

    fn admitted_for(&self, sink: httpd_rs_verified::TransformValueSink) -> bool {
        self.segments.iter().all(|segment| {
            let class = match segment {
                ValueSegment::Literal(_) => httpd_rs_verified::TransformValueClass::Literal,
                ValueSegment::Variable(variable) => variable.provenance(),
            };
            httpd_rs_verified::transform_value_class_admit(sink, class)
        })
    }

    pub fn evaluate(
        &self,
        mut resolve: impl FnMut(&ValueVariable) -> Option<Vec<u8>>,
    ) -> Result<Vec<u8>, &'static str> {
        let mut output = Vec::new();
        for segment in &self.segments {
            let value = match segment {
                ValueSegment::Literal(value) => value.clone(),
                ValueSegment::Variable(variable) => {
                    resolve(variable).ok_or("transformation variable is unavailable")?
                }
            };
            let Some(next) = httpd_rs_verified::transform_output_append(
                output.len() as u64,
                value.len() as u64,
                MAX_TRANSFORM_VALUE_BYTES as u64,
            ) else {
                return Err("transformation value exceeds its runtime byte bound");
            };
            output.extend_from_slice(&value);
            debug_assert_eq!(output.len() as u64, next);
        }
        Ok(output)
    }
}

fn parse_variable(name: &str) -> Result<ValueVariable, String> {
    let variable = match name {
        "host" => ValueVariable::Host,
        "http_host" => ValueVariable::HttpHost,
        "remote_addr" => ValueVariable::RemoteAddr,
        "proxy_add_x_forwarded_for" => ValueVariable::ProxyAddXForwardedFor,
        "proxy_host" => ValueVariable::ProxyHost,
        "scheme" => ValueVariable::Scheme,
        "http_upgrade" => ValueVariable::HttpUpgrade,
        // This is the conventional finite map of $http_upgrade to
        // "upgrade"/"close". nginx_frontend accepts only that exact map.
        "connection_upgrade" => ValueVariable::ConnectionUpgrade,
        "server_port" => ValueVariable::ServerPort,
        "server_name" => ValueVariable::ServerName,
        "request_uri" => ValueVariable::RequestUri,
        "uri" => ValueVariable::Uri,
        "document_uri" => ValueVariable::DocumentUri,
        "request_method" => ValueVariable::RequestMethod,
        "query_string" | "args" => ValueVariable::QueryString,
        "content_type" => ValueVariable::ContentType,
        "content_length" => ValueVariable::ContentLength,
        "document_root" => ValueVariable::DocumentRoot,
        "realpath_root" => ValueVariable::RealPathRoot,
        "fastcgi_script_name" => ValueVariable::FastCgiScriptName,
        "fastcgi_path_info" | "path_info" => ValueVariable::FastCgiPathInfo,
        "request_filename" => ValueVariable::RequestFilename,
        "server_protocol" => ValueVariable::ServerProtocol,
        "https" => ValueVariable::Https,
        "remote_port" => ValueVariable::RemotePort,
        "server_addr" => ValueVariable::ServerAddr,
        "gateway_interface" => ValueVariable::GatewayInterface,
        "server_software" => ValueVariable::ServerSoftware,
        _ if name.starts_with("http_") && name.len() > 5 => {
            ValueVariable::HttpHeader(name[5..].replace('_', "-"))
        }
        _ if name.starts_with("cookie_") && name.len() > 7 => {
            ValueVariable::Cookie(name[7..].to_string())
        }
        _ if name.starts_with("arg_") && name.len() > 4 => {
            ValueVariable::Argument(name[4..].to_string())
        }
        _ => return Err(format!("unsupported transformation variable '${name}'")),
    };
    Ok(variable)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeaderTransform {
    pub name: String,
    pub value: ValueExpr,
}

impl ProxyHeaderTransform {
    pub fn new(name: &str, value: &str) -> Result<Self, String> {
        if !httpd_rs_verified::proxy_header_admit(name.as_bytes(), b"") {
            return Err(format!("invalid proxy header name '{name}'"));
        }
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "transfer-encoding" | "te" | "trailer") {
            return Err(format!("proxy header '{name}' is owned by the serializer"));
        }
        if lower == "content-length" {
            return Err("proxy Content-Length is owned by the serializer".into());
        }
        let expression = ValueExpr::parse(value)?;
        let sink = match lower.as_str() {
            "host" => httpd_rs_verified::TransformValueSink::HostHeader,
            "x-forwarded-for" => httpd_rs_verified::TransformValueSink::ForwardedForHeader,
            "connection" => httpd_rs_verified::TransformValueSink::ConnectionHeader,
            "upgrade" => httpd_rs_verified::TransformValueSink::UpgradeHeader,
            _ => httpd_rs_verified::TransformValueSink::OrdinaryHeader,
        };
        if !expression.admitted_for(sink) {
            return Err(format!(
                "proxy header '{name}' uses a transformation source that is not admitted for that sink"
            ));
        }
        if lower == "connection" {
            let allowed = matches!(
                expression.segments(),
                [ValueSegment::Literal(value)]
                    if matches!(value.as_slice(), b"" | b"close" | b"keep-alive" | b"upgrade" | b"Upgrade")
            ) || matches!(
                expression.segments(),
                [ValueSegment::Variable(ValueVariable::ConnectionUpgrade)]
            );
            if !allowed {
                return Err("Connection may only be close, keep-alive, upgrade, or the finite $connection_upgrade map".into());
            }
        }
        if lower == "upgrade"
            && !matches!(
                expression.segments(),
                [ValueSegment::Literal(value)] if value.is_empty()
            )
            && !matches!(
                expression.segments(),
                [ValueSegment::Variable(ValueVariable::HttpUpgrade)]
            )
        {
            return Err("Upgrade may only be empty or $http_upgrade".into());
        }
        Ok(Self {
            name: lower,
            value: expression,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiParamTransform {
    pub name: String,
    pub value: ValueExpr,
    pub only_if_not_empty: bool,
}

impl FastCgiParamTransform {
    pub fn new(name: &str, value: &str, only_if_not_empty: bool) -> Result<Self, String> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(format!("invalid FastCGI parameter name '{name}'"));
        }
        let expression = ValueExpr::parse(value)?;
        let upper = name.to_ascii_uppercase();
        let sink = if upper == "SCRIPT_FILENAME" {
            httpd_rs_verified::TransformValueSink::FastCgiScriptFilename
        } else if matches!(
            upper.as_str(),
            "PHP_VALUE" | "PHP_ADMIN_VALUE" | "PHP_FLAG" | "PHP_ADMIN_FLAG"
        ) {
            httpd_rs_verified::TransformValueSink::PhpConfiguration
        } else {
            httpd_rs_verified::TransformValueSink::FastCgiOrdinary
        };
        if !expression.admitted_for(sink) {
            return Err(format!(
                "FastCGI parameter '{name}' uses a transformation source that is not admitted for that sink"
            ));
        }
        Ok(Self {
            name: upper,
            value: expression,
            only_if_not_empty,
        })
    }
}

pub fn request_value(
    variable: &ValueVariable,
    req: &crate::http::Request,
    peer: IpAddr,
    https: bool,
    host_name: &str,
    server_name: &str,
    server_port: u16,
) -> Option<Vec<u8>> {
    let header = |name: &str| {
        req.header(name)
            .map(|value| value.to_vec())
            .unwrap_or_default()
    };
    Some(match variable {
        ValueVariable::Host => host_name.as_bytes().to_vec(),
        ValueVariable::HttpHost => header("host"),
        ValueVariable::RemoteAddr | ValueVariable::ProxyAddXForwardedFor => {
            peer.to_string().into_bytes()
        }
        ValueVariable::Scheme => {
            if https {
                b"https".to_vec()
            } else {
                b"http".to_vec()
            }
        }
        ValueVariable::HttpUpgrade => header("upgrade"),
        ValueVariable::ConnectionUpgrade => {
            if req.header("upgrade").is_some_and(|value| !value.is_empty()) {
                b"upgrade".to_vec()
            } else {
                b"close".to_vec()
            }
        }
        ValueVariable::ServerPort => server_port.to_string().into_bytes(),
        ValueVariable::ServerName => server_name.as_bytes().to_vec(),
        ValueVariable::RequestUri => req.target.clone(),
        ValueVariable::Uri | ValueVariable::DocumentUri => req.raw_path.clone(),
        ValueVariable::RequestMethod => req.method.as_bytes().to_vec(),
        ValueVariable::QueryString => req.query.clone(),
        ValueVariable::ContentType => header("content-type"),
        ValueVariable::ContentLength => {
            if let Some(value) = req.header("content-length") {
                value.to_vec()
            } else if req.body_len() > 0 {
                req.body_len().to_string().into_bytes()
            } else {
                Vec::new()
            }
        }
        ValueVariable::HttpHeader(name) => header(name),
        ValueVariable::Cookie(name) => cookie_value(req.header("cookie"), name),
        ValueVariable::Argument(name) => argument_value(&req.query, name),
        ValueVariable::ProxyHost
        | ValueVariable::DocumentRoot
        | ValueVariable::RealPathRoot
        | ValueVariable::FastCgiScriptName
        | ValueVariable::FastCgiPathInfo
        | ValueVariable::RequestFilename
        | ValueVariable::ServerProtocol
        | ValueVariable::Https
        | ValueVariable::RemotePort
        | ValueVariable::ServerAddr
        | ValueVariable::GatewayInterface
        | ValueVariable::ServerSoftware => return None,
    })
}

fn cookie_value(header: Option<&[u8]>, name: &str) -> Vec<u8> {
    let Some(header) = header else {
        return Vec::new();
    };
    for pair in header.split(|byte| *byte == b';') {
        let pair = pair.strip_prefix(b" ").unwrap_or(pair);
        let Some(split) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if pair[..split].eq_ignore_ascii_case(name.as_bytes()) {
            return pair[split + 1..].to_vec();
        }
    }
    Vec::new()
}

fn argument_value(query: &[u8], name: &str) -> Vec<u8> {
    for pair in query.split(|byte| *byte == b'&') {
        let split = pair
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(pair.len());
        if pair[..split] == name.as_bytes()[..] {
            return pair.get(split + 1..).unwrap_or_default().to_vec();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route<T>(matcher: RouteMatcher, policy: T, order: usize) -> Route<T> {
        Route {
            matcher,
            policy,
            declaration_order: order,
        }
    }

    fn nginx_regex(pattern: &str, caseless: bool) -> Regex {
        Regex::compile_nginx(
            pattern,
            if caseless {
                httpd_rs_verified::NginxRegexModifier::Caseless
            } else {
                httpd_rs_verified::NginxRegexModifier::Sensitive
            },
        )
        .unwrap()
    }

    #[test]
    fn nginx_location_selection_is_exact_prefix_then_regex() {
        let routes = vec![
            route(
                RouteMatcher::Prefix {
                    value: "/".into(),
                    suppress_regex: false,
                },
                "root",
                0,
            ),
            route(
                RouteMatcher::Prefix {
                    value: "/images/".into(),
                    suppress_regex: false,
                },
                "images",
                1,
            ),
            route(
                RouteMatcher::Regex {
                    value: "[.]php$".into(),
                    regex: nginx_regex("[.]php$", false),
                },
                "php",
                2,
            ),
            route(RouteMatcher::Exact("/images/logo.php".into()), "exact", 3),
        ];
        assert_eq!(select_nginx_route(&routes, "/x").unwrap().policy, "root");
        assert_eq!(
            select_nginx_route(&routes, "/images/x.png").unwrap().policy,
            "images"
        );
        assert_eq!(
            select_nginx_route(&routes, "/images/x.php").unwrap().policy,
            "php"
        );
        assert_eq!(
            select_nginx_route(&routes, "/images/logo.php")
                .unwrap()
                .policy,
            "exact"
        );
    }

    #[test]
    fn caret_prefix_suppresses_regex() {
        let routes = vec![
            route(
                RouteMatcher::Prefix {
                    value: "/assets/".into(),
                    suppress_regex: true,
                },
                "assets",
                0,
            ),
            route(
                RouteMatcher::Regex {
                    value: "[.]php$".into(),
                    regex: nginx_regex("[.]php$", false),
                },
                "php",
                1,
            ),
        ];
        assert_eq!(
            select_nginx_route(&routes, "/assets/x.php").unwrap().policy,
            "assets"
        );
    }

    #[test]
    fn nginx_server_selection_uses_nginx_name_precedence() {
        let program = RouteProgram::<()>::nginx(
            vec![vec![], vec![], vec![], vec![]],
            vec![
                vec!["_".into()],
                vec!["*.example.test".into()],
                vec!["*.deep.example.test".into()],
                vec!["api.deep.example.test".into(), "mail.*".into()],
            ],
        )
        .unwrap();
        let candidates = [0, 1, 2, 3];
        assert_eq!(
            program.select_nginx_server(&candidates, Some("api.deep.example.test:443")),
            Some(3)
        );
        assert_eq!(
            program.select_nginx_server(&candidates, Some("www.deep.example.test")),
            Some(2)
        );
        assert_eq!(
            program.select_nginx_server(&candidates, Some("mail.invalid")),
            Some(3)
        );
        assert_eq!(
            program.select_nginx_server(&candidates, Some("unmatched.invalid")),
            Some(0)
        );
        let dot_heavy = format!("mail.{}", "x.".repeat(200));
        assert!(dot_heavy.len() > MAX_NGINX_AUTHORITY_NAME_BYTES);
        assert_eq!(
            program.select_nginx_server(&candidates, Some(&dot_heavy)),
            Some(0),
            "oversized reg-names must not enter wildcard suffix hashing"
        );
        program.assert_nginx_refinement(
            &[],
            &[
                "api.deep.example.test:443",
                "www.deep.example.test",
                "mail.invalid",
                "unmatched.invalid",
                &dot_heavy,
            ],
        );
    }

    #[test]
    fn indexed_location_machine_refines_the_linear_reference() {
        let routes = vec![
            route(
                RouteMatcher::Prefix {
                    value: "/".into(),
                    suppress_regex: false,
                },
                0usize,
                7,
            ),
            route(
                RouteMatcher::Regex {
                    value: "[.]php$".into(),
                    regex: nginx_regex("[.]php$", false),
                },
                1,
                3,
            ),
            route(
                RouteMatcher::Prefix {
                    value: "/assets/".into(),
                    suppress_regex: true,
                },
                2,
                2,
            ),
            route(RouteMatcher::Exact("/exact".into()), 3, 9),
            route(
                RouteMatcher::Prefix {
                    value: "/images/deep/".into(),
                    suppress_regex: false,
                },
                4,
                1,
            ),
            route(
                RouteMatcher::Regex {
                    value: "^/images/".into(),
                    regex: nginx_regex("^/images/", false),
                },
                5,
                4,
            ),
        ];
        let expected = [
            "/",
            "/exact",
            "/exact/child",
            "/assets/x.php",
            "/images/x.txt",
            "/images/deep/x.php",
            "/other.php",
            "/missing",
        ];
        let program = RouteProgram::nginx(vec![routes.clone()], vec![vec!["_".into()]])
            .expect("bounded route program");
        for path in expected {
            assert_eq!(
                program.select(0, path),
                select_nginx_route(&routes, path).map(|route| &route.policy),
                "indexed and reference selectors diverged for {path}"
            );
        }
        program.assert_nginx_refinement(&expected, &[]);
    }

    #[test]
    fn nginx_route_index_rejects_ambiguous_source_identity() {
        let routes = vec![
            route(RouteMatcher::Exact("/exact".into()), 1usize, 4),
            route(
                RouteMatcher::Prefix {
                    value: "/".into(),
                    suppress_regex: false,
                },
                2usize,
                4,
            ),
        ];
        assert!(RouteProgram::nginx(vec![routes], vec![vec!["_".into()]]).is_err());
    }

    #[test]
    fn common_ir_plan_gate_is_source_neutral_after_route_certification() {
        let apache = RouteProgram::<()>::Apache;
        let nginx = RouteProgram::<()>::nginx(vec![Vec::new()], vec![vec!["_".into()]])
            .expect("empty nginx route index is a complete certified partition");
        assert!(apache.is_refined());
        assert!(nginx.is_refined());
        let apache_admit = httpd_rs_verified::common_ir_request_plan_admit(
            apache.source_kind(),
            true,
            apache.is_refined(),
            true,
            true,
        );
        let nginx_admit = httpd_rs_verified::common_ir_request_plan_admit(
            nginx.source_kind(),
            true,
            nginx.is_refined(),
            true,
            true,
        );
        assert_eq!(apache_admit, nginx_admit);
        assert!(apache_admit);
    }

    #[test]
    fn nginx_name_table_enforces_configuration_resource_bounds() {
        let too_many = vec![Vec::<String>::new(); MAX_NGINX_SERVERS + 1];
        assert!(NginxServerNameTable::new(too_many).is_err());
        let oversized = vec![vec!["x".repeat(MAX_SERVER_NAME_BYTES + 1)]];
        assert!(NginxServerNameTable::new(oversized).is_err());

        let one_server = (0..MAX_ROUTES_PER_SERVER)
            .map(|index| route(RouteMatcher::Exact(format!("/route-{index}")), index, index))
            .collect::<Vec<_>>();
        let servers = vec![one_server; MAX_NGINX_ROUTES / MAX_ROUTES_PER_SERVER + 1];
        let names = vec![vec!["bounded.test".to_string()]; servers.len()];
        assert!(RouteProgram::nginx(servers, names).is_err());
    }

    #[test]
    fn transform_grammar_is_closed() {
        assert!(ValueExpr::parse("$scheme://$host$request_uri").is_ok());
        assert!(ValueExpr::parse("$arbitrary_module_variable").is_err());
        assert!(ProxyHeaderTransform::new("Connection", "$http_connection").is_err());
        assert!(ProxyHeaderTransform::new("Connection", "$connection_upgrade").is_ok());
        assert!(ProxyHeaderTransform::new("Host", "$host").is_ok());
        assert!(ProxyHeaderTransform::new("Host", "$http_host").is_ok());
        assert!(ProxyHeaderTransform::new("Host", "$request_uri").is_err());
        assert!(ProxyHeaderTransform::new("X-Forwarded-For", "$proxy_add_x_forwarded_for").is_ok());
        assert!(ProxyHeaderTransform::new("X-Forwarded-For", "$http_x_forwarded_for").is_err());
        assert!(ProxyHeaderTransform::new("Transfer-Encoding", "chunked").is_err());
        assert!(ProxyHeaderTransform::new("Content-Length", "").is_err());
        assert!(ValueExpr::parse("bad\0value").is_err());
        assert!(FastCgiParamTransform::new(
            "SCRIPT_FILENAME",
            "$document_root$fastcgi_script_name",
            false,
        )
        .is_ok());
        assert!(
            FastCgiParamTransform::new("SCRIPT_FILENAME", "$document_root$uri", false).is_err()
        );
        assert!(FastCgiParamTransform::new("PHP_VALUE", "memory_limit=64M", false).is_ok());
        assert!(FastCgiParamTransform::new("PHP_VALUE", "$arg_override", false).is_err());

        let bounded = ValueExpr::parse("$request_uri").unwrap();
        assert!(bounded
            .evaluate(|_| Some(vec![b'x'; MAX_TRANSFORM_VALUE_BYTES]))
            .is_ok());
        assert!(bounded
            .evaluate(|_| Some(vec![b'x'; MAX_TRANSFORM_VALUE_BYTES + 1]))
            .is_err());
    }
}
