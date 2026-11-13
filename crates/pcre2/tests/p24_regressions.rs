//! Fixed regressions from adversarial pass P24.

use httpd_rs_pcre2::bytes as rust;
use httpd_rs_pcre2::ErrorKind;

#[test]
fn p24_b_nested_optional_repetition_is_charged_for_pike_active_paths() {
    // This shape previously received essentially the same charge as the flat
    // repetition below, despite taking 262–292 ms through the PikeVM versus
    // under 1 ms for the flat lazy-DFA-compatible form.
    let nested = rust::Regex::new(r"1(?:[[:^alpha:]]{0,3}){4208}a").unwrap();
    let subject = vec![b'1'; 1328];
    assert_eq!(
        nested.captures(&subject).unwrap_err().kind(),
        ErrorKind::ResourceLimit
    );

    // Exact repetitions do not acquire the optional-path multiplier. Keep
    // the fast equivalent-work control admitted at the default work ceiling.
    let flat = rust::Regex::new(r"[[:^alpha:]]{12624}").unwrap();
    assert!(flat.captures(&subject).is_ok());
}
