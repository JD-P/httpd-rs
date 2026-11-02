use std::net::IpAddr;
use std::sync::Arc;

use vapached::resource::{with_resource_context, ResourceBudget};

#[test]
fn request_scoped_admission_fails_without_a_context() {
    let budget = Arc::new(ResourceBudget::default());
    assert!(budget.try_request_bytes().is_err());
    assert!(budget.try_response_bytes().is_err());
    assert!(budget.try_dynamic(8).is_err());
    assert!(budget.try_spool(1024, 8).is_err());
    assert!(budget.try_response_body_read().is_err());
}

#[test]
fn request_scoped_admission_rejects_a_different_process_ledger() {
    let first = Arc::new(ResourceBudget::default());
    let second = Arc::new(ResourceBudget::default());
    let context = first.context(IpAddr::from([192, 0, 2, 1]));
    with_resource_context(context, || {
        assert!(second.try_request_bytes().is_err());
        assert!(second.try_response_bytes().is_err());
        assert!(second.try_dynamic(8).is_err());
        assert!(second.try_spool(1024, 8).is_err());
        assert!(second.try_response_body_read().is_err());
    });
}
