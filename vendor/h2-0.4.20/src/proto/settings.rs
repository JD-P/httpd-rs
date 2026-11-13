use crate::codec::UserError;
use crate::error::Reason;
use crate::proto::*;
use std::task::{Context, Poll};

#[derive(Debug)]
pub(crate) struct Settings {
    /// The sole SETTINGS exchange phase. Payloads are retained separately
    /// while this verified state says they are queued or awaiting an ACK.
    sync: httpd_rs_verified::H2SettingsSync,
    local: Option<frame::Settings>,
    /// Received SETTINGS frame pending processing. The ACK must be written to
    /// the socket first then the settings applied **before** receiving any
    /// further frames.
    remote: Option<frame::Settings>,
}

impl Settings {
    pub(crate) fn new(local: frame::Settings) -> Self {
        Settings {
            // We assume the initial local SETTINGS were flushed during
            // the handshake process.
            sync: httpd_rs_verified::H2SettingsSync {
                local: httpd_rs_verified::H2LocalSettingsPhase::WaitingAck,
                remote_pending: false,
                remote_initial_seen: false,
            },
            local: Some(local),
            remote: None,
        }
    }

    pub(crate) fn recv_settings<T, B, C, P>(
        &mut self,
        frame: frame::Settings,
        codec: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Result<(), Error>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if frame.is_ack() {
            match self.sync.local {
                httpd_rs_verified::H2LocalSettingsPhase::WaitingAck => {
                    let local = self
                        .local
                        .as_ref()
                        .expect("SETTINGS WaitingAck phase lost its payload");
                    tracing::debug!("received settings ACK; applying {:?}", local);

                    if let Some(max) = local.max_frame_size() {
                        codec.set_max_recv_frame_size(max as usize);
                    }

                    if let Some(max) = local.max_header_list_size() {
                        codec.set_max_recv_header_list_size(max as usize);
                    }

                    if let Some(val) = local.header_table_size() {
                        codec.set_recv_header_table_size(val as usize);
                    }

                    streams.apply_local_settings(local)?;
                    self.sync = httpd_rs_verified::h2_settings_sync_step(
                        self.sync,
                        httpd_rs_verified::H2SettingsSyncEvent::ReceiveAck,
                    )
                    .expect("WaitingAck must accept its sole ACK");
                    self.local = None;
                    Ok(())
                }
                httpd_rs_verified::H2LocalSettingsPhase::ToSend
                | httpd_rs_verified::H2LocalSettingsPhase::Synced => {
                    // We haven't sent any SETTINGS frames to be ACKed, so
                    // this is very bizarre! Remote is either buggy or malicious.
                    proto_err!(conn: "received unexpected settings ack");
                    Err(Error::library_go_away(Reason::PROTOCOL_ERROR))
                }
            }
        } else {
            let Some(next) = httpd_rs_verified::h2_settings_sync_step(
                self.sync,
                httpd_rs_verified::H2SettingsSyncEvent::ReceiveRemote,
            ) else {
                proto_err!(conn: "received SETTINGS before the previous frame was applied");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            };
            debug_assert!(self.remote.is_none());
            self.sync = next;
            self.remote = Some(frame);
            Ok(())
        }
    }

    pub(crate) fn send_settings(&mut self, frame: frame::Settings) -> Result<(), UserError> {
        assert!(!frame.is_ack());
        match self.sync.local {
            httpd_rs_verified::H2LocalSettingsPhase::ToSend
            | httpd_rs_verified::H2LocalSettingsPhase::WaitingAck => {
                Err(UserError::SendSettingsWhilePending)
            }
            httpd_rs_verified::H2LocalSettingsPhase::Synced => {
                tracing::trace!("queue to send local settings: {:?}", frame);
                self.sync = httpd_rs_verified::h2_settings_sync_step(
                    self.sync,
                    httpd_rs_verified::H2SettingsSyncEvent::QueueLocal,
                )
                .expect("Synced SETTINGS phase must permit one queued update");
                self.local = Some(frame);
                Ok(())
            }
        }
    }

    pub(crate) fn poll_send<T, B, C, P>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Poll<Result<(), Error>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if let Some(settings) = self.remote.clone() {
            if !dst.poll_ready(cx)?.is_ready() {
                return Poll::Pending;
            }

            // Create an ACK settings frame
            let frame = frame::Settings::ack();

            // Buffer the settings frame
            dst.buffer(frame.into()).expect("invalid settings frame");

            tracing::trace!("ACK sent; applying settings");

            let is_initial = !self.sync.remote_initial_seen;
            streams.apply_remote_settings(&settings, is_initial)?;

            if let Some(val) = settings.header_table_size() {
                dst.set_send_header_table_size(val as usize);
            }

            if let Some(val) = settings.max_frame_size() {
                dst.set_max_send_frame_size(val as usize);
            }
            self.sync = httpd_rs_verified::h2_settings_sync_step(
                self.sync,
                httpd_rs_verified::H2SettingsSyncEvent::ApplyRemote,
            )
            .expect("a retained remote SETTINGS payload must be pending");
        }

        self.remote = None;

        match self.sync.local {
            httpd_rs_verified::H2LocalSettingsPhase::ToSend => {
                if !dst.poll_ready(cx)?.is_ready() {
                    return Poll::Pending;
                }

                // Buffer the settings frame
                let settings = self
                    .local
                    .as_ref()
                    .expect("SETTINGS ToSend phase lost its payload");
                dst.buffer(settings.clone().into())
                    .expect("invalid settings frame");
                tracing::trace!("local settings sent; waiting for ack: {:?}", settings);

                self.sync = httpd_rs_verified::h2_settings_sync_step(
                    self.sync,
                    httpd_rs_verified::H2SettingsSyncEvent::LocalSent,
                )
                .expect("ToSend SETTINGS phase must wait for its ACK");
            }
            httpd_rs_verified::H2LocalSettingsPhase::WaitingAck => {
                debug_assert!(self.local.is_some());
            }
            httpd_rs_verified::H2LocalSettingsPhase::Synced => {
                debug_assert!(self.local.is_none());
            }
        }

        Poll::Ready(Ok(()))
    }
}
