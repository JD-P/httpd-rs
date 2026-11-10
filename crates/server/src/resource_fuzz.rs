use super::*;

const MAX_STEPS: usize = 128;
const MAX_ACTIVE: usize = 272;
const FUZZ_DYNAMIC_LIMIT: u64 = 16;
const FUZZ_H1_LIMIT: u64 = 64;
const FUZZ_H1_CLIENT_LIMIT: u64 = 32;
const FUZZ_SPOOL_BYTES: u64 = 64 * 1024;
const FUZZ_SPOOL_FILES: u64 = 16;
const SLOT_KINDS: [SlotKind; SlotKind::COUNT] = [
    SlotKind::DynamicBackend,
    SlotKind::H2Stream,
    SlotKind::SlowInput,
    SlotKind::SlowOutput,
    SlotKind::ResponseBodyRead,
    SlotKind::Websocket,
    SlotKind::ExpensiveCpu,
    SlotKind::PendingConnection,
    SlotKind::H1Connection,
    SlotKind::RequestWorker,
    SlotKind::RequestBodyWorker,
    SlotKind::H2Connection,
    SlotKind::TlsHandshake,
    SlotKind::RewriteProgram,
    SlotKind::SpoolFile,
    SlotKind::SlowSpoolFile,
    SlotKind::FilesystemWork,
];
const BYTE_KINDS: [ByteKind; ByteKind::COUNT] = [
    ByteKind::Spool,
    ByteKind::SlowSpool,
    ByteKind::RequestResident,
    ByteKind::ResponseResident,
    ByteKind::SlowResponseResident,
    ByteKind::PolicyExpansion,
    ByteKind::CacheResident,
];

#[derive(Default)]
struct CampaignState {
    residents: Vec<ResidentLease>,
    spools: Vec<SpoolLease>,
    dynamics: Vec<DynamicLease>,
    outputs: Vec<SlowOutputAdmission>,
    queued_h2_outputs: Vec<(ResourceContext, QueuedH2TransportLease)>,
    reads: Vec<ResponseBodyReadLease>,
    websockets: Vec<WebsocketLease>,
}

impl CampaignState {
    fn clear(&mut self) {
        self.outputs.clear();
        self.queued_h2_outputs.clear();
        self.reads.clear();
        self.websockets.clear();
        self.dynamics.clear();
        self.spools.clear();
        self.residents.clear();
    }

    fn active_contexts(&self) -> Vec<ResourceContext> {
        let mut contexts = Vec::new();
        contexts.extend(
            self.residents
                .iter()
                .map(|lease| lease.bytes.context.clone()),
        );
        for lease in &self.spools {
            contexts.push(lease.bytes.context.clone());
            contexts.push(
                lease
                    .file_slot
                    .as_ref()
                    .expect("active spool file slot")
                    .context
                    .clone(),
            );
        }
        contexts.extend(
            self.dynamics
                .iter()
                .filter_map(|lease| lease._slot.as_ref().map(|slot| slot.context.clone())),
        );
        contexts.extend(self.outputs.iter().map(|output| output.context.clone()));
        contexts.extend(
            self.queued_h2_outputs
                .iter()
                .map(|(context, _lease)| context.clone()),
        );
        contexts.extend(self.reads.iter().map(|lease| lease._slot.context.clone()));
        contexts.extend(
            self.websockets
                .iter()
                .map(|lease| lease._slot.context.clone()),
        );
        contexts
    }

    fn clear_and_assert_scopes(&mut self) {
        let contexts = self.active_contexts();
        self.clear();
        assert_scopes_empty(&contexts);
    }
}

fn campaign_budget() -> Arc<ResourceBudget> {
    Arc::new(ResourceBudget {
        // Fixed parent limits make a corpus portable across developer and CI
        // hosts while still forcing child/parent contention and rollback.
        physical_limits: [512, 512, 256 * 1024 * 1024],
        disk_byte_limit: 8 * FUZZ_SPOOL_BYTES,
        disk_file_limit: 2 * FUZZ_SPOOL_FILES,
        transport_byte_limit: FUZZ_DYNAMIC_LIMIT * TRANSPORT_BUFFER_CHARGE,
        ..ResourceBudget::default()
    })
}

fn clients() -> [IpAddr; 6] {
    [
        IpAddr::from([192, 0, 2, 1]),
        IpAddr::from([192, 0, 2, 2]),
        "::ffff:192.0.2.1".parse().expect("static mapped IPv4"),
        "2001:db8:1::1".parse().expect("static IPv6"),
        "2001:db8:1::ffff".parse().expect("static IPv6"),
        "2001:db8:2::1".parse().expect("static IPv6"),
    ]
}

fn sticky_contexts(budget: &Arc<ResourceBudget>, clients: &[IpAddr]) -> Vec<ResourceContext> {
    clients
        .iter()
        .flat_map(|client| [budget.context(*client), budget.context(*client)])
        .collect()
}

fn sticky_context(contexts: &[ResourceContext], selector: u8) -> ResourceContext {
    contexts[usize::from(selector) % contexts.len()].clone()
}

fn batch_context(
    budget: &Arc<ResourceBudget>,
    contexts: &[ResourceContext],
    clients: &[IpAddr],
    selector: u8,
    iteration: usize,
) -> ResourceContext {
    if selector & 0x80 != 0 {
        return sticky_context(contexts, selector.wrapping_add(iteration as u8));
    }
    let offset = if selector & 0x40 == 0 { iteration } else { 0 };
    let client = clients[(usize::from(selector) + offset) % clients.len()];
    budget.context(client)
}

fn boundary_amount(code: u8) -> u64 {
    match code & 0x0f {
        0 => 0,
        1 => 1,
        2 => 4 * 1024 - 1,
        3 => 4 * 1024,
        4 => FUZZ_SPOOL_BYTES - 1,
        5 => FUZZ_SPOOL_BYTES,
        6 => MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST - 1,
        7 => MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST,
        8 => MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST + 1,
        9 => MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT - 1,
        10 => MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
        11 => MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT + 1,
        12 => MAX_RESPONSE_RESIDENT_BYTES,
        13 => MAX_RESPONSE_RESIDENT_BYTES + 1,
        14 => u64::MAX - 1,
        _ => u64::MAX,
    }
}

fn batch_count(code: u8) -> usize {
    const COUNTS: [usize; 15] = [1, 2, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 129, 257];
    COUNTS[usize::from(code) % COUNTS.len()]
}

fn selected<T>(items: &[T], selector: u8) -> Option<usize> {
    (!items.is_empty()).then(|| usize::from(selector) % items.len())
}

fn insert_bounded<T>(items: &mut Vec<T>, value: T, selector: u8) {
    if items.len() >= MAX_ACTIVE {
        let index = usize::from(selector) % items.len();
        drop(items.swap_remove(index));
    }
    items.push(value);
}

fn slot_process_limit(kind: SlotKind) -> u64 {
    match kind {
        SlotKind::DynamicBackend => FUZZ_DYNAMIC_LIMIT,
        SlotKind::H2Stream => MAX_H2_STREAMS,
        SlotKind::SlowInput => MAX_SLOW_INPUTS,
        SlotKind::SlowOutput => MAX_SLOW_OUTPUTS,
        SlotKind::ResponseBodyRead => MAX_RESPONSE_BODY_READS,
        SlotKind::Websocket => MAX_WEBSOCKET_TUNNELS,
        SlotKind::H1Connection => FUZZ_H1_LIMIT,
        SlotKind::SpoolFile => FUZZ_SPOOL_FILES,
        SlotKind::SlowSpoolFile => (FUZZ_SPOOL_FILES + 3) / 4,
        _ => 0,
    }
}

fn slot_client_limit(kind: SlotKind) -> u64 {
    match kind {
        SlotKind::DynamicBackend => MAX_DYNAMIC_REQUESTS_PER_CLIENT,
        SlotKind::H2Stream => MAX_H2_STREAMS_PER_CLIENT,
        SlotKind::SlowInput => MAX_SLOW_INPUTS_PER_CLIENT,
        SlotKind::SlowOutput => MAX_SLOW_OUTPUTS_PER_CLIENT,
        SlotKind::ResponseBodyRead => MAX_RESPONSE_BODY_READS_PER_CLIENT,
        SlotKind::Websocket => MAX_WEBSOCKETS_PER_CLIENT,
        SlotKind::H1Connection => FUZZ_H1_CLIENT_LIMIT,
        SlotKind::SpoolFile | SlotKind::SlowSpoolFile => (FUZZ_SPOOL_FILES + 3) / 4,
        _ => 0,
    }
}

fn byte_process_limit(kind: ByteKind) -> u64 {
    match kind {
        ByteKind::Spool => FUZZ_SPOOL_BYTES,
        ByteKind::SlowSpool => (FUZZ_SPOOL_BYTES + 3) / 4,
        ByteKind::RequestResident => MAX_REQUEST_RESIDENT_BYTES,
        ByteKind::ResponseResident | ByteKind::SlowResponseResident => MAX_RESPONSE_RESIDENT_BYTES,
        ByteKind::PolicyExpansion | ByteKind::CacheResident => 0,
    }
}

fn byte_client_limit(kind: ByteKind) -> u64 {
    match kind {
        ByteKind::Spool | ByteKind::SlowSpool => (FUZZ_SPOOL_BYTES + 3) / 4,
        ByteKind::RequestResident => MAX_REQUEST_RESIDENT_BYTES_PER_CLIENT,
        ByteKind::ResponseResident | ByteKind::SlowResponseResident => {
            MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT
        }
        ByteKind::PolicyExpansion | ByteKind::CacheResident => 0,
    }
}

fn assert_consistent(budget: &ResourceBudget) {
    let snapshot = budget.transition_snapshot();

    for index in 0..SlotKind::COUNT {
        let kind = SLOT_KINDS[index];
        assert!(snapshot.slots[index] <= slot_process_limit(kind));
    }
    for index in 0..ByteKind::COUNT {
        let kind = BYTE_KINDS[index];
        assert!(snapshot.bytes[index] <= byte_process_limit(kind));
    }
    for index in 0..PhysicalKind::COUNT {
        assert!(snapshot.physical[index] <= budget.physical_limits[index]);
    }
    assert!(snapshot.disk_bytes <= budget.disk_byte_limit);
    assert!(snapshot.disk_files <= budget.disk_file_limit);
    assert!(snapshot.transport_bytes <= budget.transport_byte_limit);

    let slot_clients = budget
        .slot_clients
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut client_slots = [0_u64; SlotKind::COUNT];
    for usage in slot_clients.values() {
        assert!(usage.iter().any(|value| *value != 0));
        for index in 0..SlotKind::COUNT {
            let kind = SLOT_KINDS[index];
            assert!(usage[index] <= slot_client_limit(kind));
            client_slots[index] = client_slots[index]
                .checked_add(usage[index])
                .expect("client slot usage overflowed");
        }
    }
    assert_eq!(client_slots, snapshot.slots);
    drop(slot_clients);

    let byte_clients = budget
        .byte_clients
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut client_bytes = [0_u64; ByteKind::COUNT];
    for usage in byte_clients.values() {
        assert!(usage.iter().any(|value| *value != 0));
        for index in 0..ByteKind::COUNT {
            let kind = BYTE_KINDS[index];
            assert!(usage[index] <= byte_client_limit(kind));
            client_bytes[index] = client_bytes[index]
                .checked_add(usage[index])
                .expect("client byte usage overflowed");
        }
    }
    assert_eq!(client_bytes, snapshot.bytes);
    drop(byte_clients);

    let ledgers = budget
        .disk_ledgers
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut filesystem_bytes = 0_u64;
    let mut filesystem_files = 0_u64;
    for ledger in ledgers.devices.values() {
        let bytes = ledger.bytes.load(Ordering::Acquire);
        let files = ledger.files.load(Ordering::Acquire);
        assert!(bytes <= ledger.byte_limit);
        assert!(files <= ledger.file_limit);
        filesystem_bytes = filesystem_bytes
            .checked_add(bytes)
            .expect("filesystem byte usage overflowed");
        filesystem_files = filesystem_files
            .checked_add(files)
            .expect("filesystem file usage overflowed");
    }
    assert_eq!(filesystem_bytes, snapshot.filesystem_bytes);
    assert_eq!(filesystem_files, snapshot.filesystem_files);
    assert_eq!(snapshot.disk_bytes, snapshot.filesystem_bytes);
    assert_eq!(snapshot.disk_files, snapshot.filesystem_files);
}

fn assert_empty(budget: &ResourceBudget) {
    assert_consistent(budget);
    let snapshot = budget.transition_snapshot();
    assert!(snapshot.slots.iter().all(|value| *value == 0));
    assert!(snapshot.bytes.iter().all(|value| *value == 0));
    assert!(snapshot.physical.iter().all(|value| *value == 0));
    assert_eq!(snapshot.disk_bytes, 0);
    assert_eq!(snapshot.disk_files, 0);
    assert_eq!(snapshot.filesystem_bytes, 0);
    assert_eq!(snapshot.filesystem_files, 0);
    assert_eq!(snapshot.transport_bytes, 0);
    assert_eq!(budget.queued_h2_outputs.load(Ordering::Acquire), 0);
}

fn assert_scopes_empty(contexts: &[ResourceContext]) {
    for context in contexts {
        assert!(context
            .local
            .slots
            .iter()
            .all(|counter| counter.load(Ordering::Acquire) == 0));
        assert!(context
            .local
            .bytes
            .iter()
            .all(|counter| counter.load(Ordering::Acquire) == 0));
    }
}

fn assert_rejected_without_change(
    budget: &ResourceBudget,
    before: &TransitionResourceSnapshot,
    rejected: bool,
) {
    if rejected {
        assert_eq!(*before, budget.transition_snapshot());
    }
}

pub(super) fn run(data: &[u8]) {
    let budget = campaign_budget();
    let foreign = campaign_budget();
    let clients = clients();
    let contexts = sticky_contexts(&budget, &clients);
    let mut state = CampaignState::default();

    for record in data.chunks(4).take(MAX_STEPS) {
        let control = record.first().copied().unwrap_or(0);
        let selector = record.get(1).copied().unwrap_or(0);
        let client_selector = record.get(2).copied().unwrap_or(0);
        let magnitude = record.get(3).copied().unwrap_or(0);
        let client = clients[usize::from(client_selector) % clients.len()];

        match control & 0x1f {
            0 | 1 => {
                let context = sticky_context(&contexts, selector);
                let lease = if control & 1 == 0 {
                    budget
                        .try_request_bytes_in(&context)
                        .expect("matching request context rejected")
                } else {
                    budget
                        .try_response_bytes_in(&context)
                        .expect("matching response context rejected")
                };
                insert_bounded(&mut state.residents, lease, selector);
            }
            2 => {
                if let Some(index) = selected(&state.residents, selector) {
                    let before = budget.transition_snapshot();
                    let result = state.residents[index].reserve(boundary_amount(magnitude));
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            3 => {
                if let Some(index) = selected(&state.residents, selector) {
                    state.residents[index].release(boundary_amount(magnitude));
                }
            }
            4 => {
                if let Some(index) = selected(&state.residents, selector) {
                    let before = budget.transition_snapshot();
                    let context = sticky_context(&contexts, client_selector);
                    let _ = state.residents[index].attribute_context(context);
                    assert_eq!(before, budget.transition_snapshot());
                }
            }
            5 => {
                if let Some(index) = selected(&state.residents, selector) {
                    let before = budget.transition_snapshot();
                    let _ = state.residents[index].attribute_response_client(client);
                    assert_eq!(before, budget.transition_snapshot());
                }
            }
            6 => {
                if let Some(index) = selected(&state.residents, selector) {
                    let before = budget.transition_snapshot();
                    let result = state.residents[index].enter_slow_output();
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            7 => {
                if let Some(index) = selected(&state.residents, selector) {
                    drop(state.residents.swap_remove(index));
                }
            }
            8 => {
                let context = sticky_context(&contexts, selector);
                if let Ok(lease) = budget.try_spool_in(FUZZ_SPOOL_BYTES, FUZZ_SPOOL_FILES, &context)
                {
                    insert_bounded(&mut state.spools, lease, selector);
                }
            }
            9 => {
                if let Some(index) = selected(&state.spools, selector) {
                    let before = budget.transition_snapshot();
                    let result = state.spools[index].reserve(boundary_amount(magnitude));
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            10 => {
                if let Some(index) = selected(&state.spools, selector) {
                    let before = budget.transition_snapshot();
                    let _ = state.spools[index].attribute_client(client);
                    assert_eq!(before, budget.transition_snapshot());
                }
            }
            11 => {
                if let Some(index) = selected(&state.spools, selector) {
                    let before = budget.transition_snapshot();
                    let result = state.spools[index].enter_slow();
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            12 => {
                if let Some(index) = selected(&state.spools, selector) {
                    drop(state.spools.swap_remove(index));
                }
            }
            13 => {
                for iteration in 0..batch_count(magnitude) {
                    let context =
                        batch_context(&budget, &contexts, &clients, client_selector, iteration);
                    if let Ok(lease) = budget.try_dynamic_in(&context, FUZZ_DYNAMIC_LIMIT) {
                        insert_bounded(&mut state.dynamics, lease, selector);
                    }
                }
            }
            14 => {
                if let Some(index) = selected(&state.dynamics, selector) {
                    state.dynamics[index].release_general_slot();
                }
            }
            15 => {
                if let Some(index) = selected(&state.dynamics, selector) {
                    drop(state.dynamics.swap_remove(index));
                }
            }
            16 => {
                for iteration in 0..batch_count(magnitude) {
                    let context =
                        batch_context(&budget, &contexts, &clients, client_selector, iteration);
                    let output = if selector & 1 == 0 {
                        budget
                            .try_h2_stream_in(&context)
                            .ok()
                            .map(|lease| SlowOutputAdmission::tracked_h2(context, lease))
                    } else {
                        context
                            .slot(
                                SlotKind::H1Connection,
                                FUZZ_H1_LIMIT,
                                Some(FUZZ_H1_CLIENT_LIMIT),
                                Some(1),
                                "fuzz HTTP/1 connection limit reached",
                            )
                            .ok()
                            .map(|lease| SlowOutputAdmission::tracked_h1(context, lease))
                    };
                    if let Some(output) = output {
                        insert_bounded(&mut state.outputs, output, selector);
                    }
                }
            }
            17 => {
                if let Some(index) = selected(&state.outputs, selector) {
                    let before = budget.transition_snapshot();
                    let result = state.outputs[index].enter_slow_input();
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            18 => {
                if let Some(index) = selected(&state.outputs, selector) {
                    let before = budget.transition_snapshot();
                    let result = state.outputs[index].leave_slow_input();
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            19 => {
                if let Some(index) = selected(&state.outputs, selector) {
                    let before = budget.transition_snapshot();
                    let result = if magnitude & 1 == 0 {
                        state.outputs[index].enter_slow()
                    } else {
                        state.outputs[index]
                            .enter_slow_with(|| Err(io::Error::other("fuzz transfer failure")))
                    };
                    assert_rejected_without_change(&budget, &before, result.is_err());
                }
            }
            20 => {
                if let Some(index) = selected(&state.outputs, selector) {
                    if magnitude & 3 == 0 {
                        let before = budget.transition_snapshot();
                        let context = state.outputs[index].context.clone();
                        match state.outputs[index].retain_queued_h2_transport() {
                            Ok(Some(lease)) => {
                                // The response task can close independently;
                                // the transport-owned head must keep the H2
                                // stream charged until its owner is dropped.
                                state.outputs[index].finish_response();
                                assert_eq!(before, budget.transition_snapshot());
                                insert_bounded(
                                    &mut state.queued_h2_outputs,
                                    (context, lease),
                                    selector,
                                );
                            }
                            Ok(None) => state.outputs[index].finish_response(),
                            Err(_) => assert_eq!(before, budget.transition_snapshot()),
                        }
                    } else if magnitude & 1 == 0 {
                        state.outputs[index].finish_response();
                    } else {
                        let output = state.outputs.swap_remove(index);
                        drop(output.finish_h1());
                    }
                }
            }
            21 => {
                if magnitude & 1 == 0 {
                    if let Some(index) = selected(&state.queued_h2_outputs, selector) {
                        drop(state.queued_h2_outputs.swap_remove(index));
                    }
                } else if let Some(index) = selected(&state.outputs, selector) {
                    drop(state.outputs.swap_remove(index));
                }
            }
            22 => {
                for iteration in 0..batch_count(magnitude) {
                    let context =
                        batch_context(&budget, &contexts, &clients, client_selector, iteration);
                    if let Ok(lease) = budget.try_response_body_read_in(&context) {
                        insert_bounded(&mut state.reads, lease, selector);
                    }
                }
            }
            23 => {
                if let Some(index) = selected(&state.reads, selector) {
                    drop(state.reads.swap_remove(index));
                }
            }
            24 => {
                for iteration in 0..batch_count(magnitude) {
                    let context =
                        batch_context(&budget, &contexts, &clients, client_selector, iteration);
                    if let Ok(slot) = context.slot(
                        SlotKind::Websocket,
                        MAX_WEBSOCKET_TUNNELS,
                        Some(MAX_WEBSOCKETS_PER_CLIENT),
                        Some(1),
                        "fuzz WebSocket limit reached",
                    ) {
                        insert_bounded(
                            &mut state.websockets,
                            WebsocketLease { _slot: slot },
                            selector,
                        );
                    }
                }
            }
            25 => {
                if let Some(index) = selected(&state.websockets, selector) {
                    drop(state.websockets.swap_remove(index));
                }
            }
            26 => {
                let before = budget.transition_snapshot();
                let foreign_before = foreign.transition_snapshot();
                let context = foreign.context(client);
                if selector & 1 == 0 {
                    if let Some(index) = selected(&state.residents, selector) {
                        assert!(state.residents[index].attribute_context(context).is_err());
                    }
                } else if let Some(index) = selected(&state.spools, selector) {
                    assert!(state.spools[index]
                        .file_slot
                        .as_mut()
                        .expect("spool file slot")
                        .attribute_context(context.clone())
                        .is_err());
                    assert!(state.spools[index]
                        .bytes
                        .attribute_context(context)
                        .is_err());
                }
                assert_eq!(before, budget.transition_snapshot());
                assert_eq!(foreign_before, foreign.transition_snapshot());
            }
            27 | 31 => state.clear_and_assert_scopes(),
            28 => {
                for iteration in 0..batch_count(magnitude) {
                    let context =
                        batch_context(&budget, &contexts, &clients, client_selector, iteration);
                    insert_bounded(
                        &mut state.outputs,
                        SlowOutputAdmission::detached(context),
                        selector,
                    );
                }
            }
            29 => {
                // Every receiver/context API must reject a mixed generation
                // before either ledger receives a partial child or parent
                // charge.
                let context = foreign.context(client);
                let before = budget.transition_snapshot();
                let foreign_before = foreign.transition_snapshot();
                assert!(budget.try_filesystem_work_in(&context).is_err());
                assert!(budget
                    .try_spool_in(FUZZ_SPOOL_BYTES, FUZZ_SPOOL_FILES, &context)
                    .is_err());
                assert!(budget.try_dynamic_in(&context, FUZZ_DYNAMIC_LIMIT).is_err());
                assert!(budget.try_h2_stream_in(&context).is_err());
                assert!(budget.try_slow_input_in(&context).is_err());
                assert!(budget.try_slow_output_in(&context).is_err());
                assert!(budget.try_request_bytes_in(&context).is_err());
                assert!(budget.try_response_bytes_in(&context).is_err());
                assert!(budget.try_response_body_read_in(&context).is_err());
                assert!(budget.try_request_rate(&context).is_err());
                assert!(budget.try_cache_write(&context, 1).is_err());
                assert!(budget.try_cache_resident(&context, 1, 1).is_err());
                assert!(budget.try_tls_handshake(&context, 1, 1, 1).is_err());
                assert!(budget.try_rewrite_program(&context, 1, 1, 1, 1).is_err());
                assert_eq!(before, budget.transition_snapshot());
                assert_eq!(foreign_before, foreign.transition_snapshot());
            }
            30 => {
                // Direct slot admission has its own identity guard; retain it
                // as a separate oracle from the higher-level helpers above.
                let context = foreign.context(client);
                let before = budget.transition_snapshot();
                assert!(budget
                    .try_slot(
                        &context,
                        SlotKind::FilesystemWork,
                        1,
                        Some(1),
                        Some(1),
                        "mixed fuzz ledger",
                    )
                    .is_err());
                assert_eq!(before, budget.transition_snapshot());
            }
            _ => unreachable!(),
        }

        assert_consistent(&budget);
        assert_consistent(&foreign);
    }

    state.clear_and_assert_scopes();
    assert_scopes_empty(&contexts);
    assert_empty(&budget);
    assert_empty(&foreign);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_transition_campaign_seed_is_conservative() {
        let mut seed = Vec::new();
        for operation in 0_u8..32 {
            seed.extend_from_slice(&[
                b'@' + operation,
                operation.wrapping_mul(17),
                operation.wrapping_mul(29),
                operation,
            ]);
        }
        run(&seed);
    }
}
