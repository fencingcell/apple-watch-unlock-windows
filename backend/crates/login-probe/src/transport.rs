//! Probe framing and one-use state. AGPL-3.0-only.
use anyhow::{bail, ensure, Result};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use watch_unlock_auth::{PendingApproval, Request, SignedApproval};
pub const MAX_PEERS: usize = 8;
pub const MAX_MESSAGE: usize = 4096;
#[derive(Default)]
pub struct Transfer {
    bytes: Vec<u8>,
    total: Option<usize>,
    finished: bool,
}
impl Transfer {
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        let result = self.push_inner(frame);
        if result.is_err() {
            self.finished = true;
            self.bytes.clear();
        }
        result
    }
    fn push_inner(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        ensure!(
            !self.finished && (5..=20).contains(&frame.len()),
            "transfer closed or invalid frame length"
        );
        let offset = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let total = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        ensure!(
            (1..=MAX_MESSAGE).contains(&total)
                && offset == self.bytes.len()
                && self.total.is_none_or(|t| t == total)
                && offset + frame.len() - 4 <= total,
            "invalid frame sequence"
        );
        self.total = Some(total);
        self.bytes.extend_from_slice(&frame[4..]);
        if self.bytes.len() == total {
            self.finished = true;
            return Ok(Some(std::mem::take(&mut self.bytes)));
        }
        Ok(None)
    }
}
struct Peer {
    pending: PendingApproval,
    json: Vec<u8>,
    offset: usize,
    transfer: Transfer,
    created: u64,
    expires: u64,
    deadline: Instant,
}
pub struct Peers {
    key: Option<Vec<u8>>,
    peers: HashMap<String, Peer>,
}
impl Peers {
    pub fn new(key: Option<Vec<u8>>) -> Self {
        Self {
            key,
            peers: HashMap::new(),
        }
    }
    pub fn remove(&mut self, peer: &str) {
        self.peers.remove(peer);
    }
    pub fn clear(&mut self) {
        self.peers.clear();
    }
    pub fn prune(&mut self, wall: u64, now: Instant) {
        self.peers
            .retain(|_, p| now < p.deadline && wall >= p.created && wall < p.expires);
    }
    pub fn start(
        &mut self,
        peer: &str,
        request: Request,
        json: Vec<u8>,
        wall: u64,
        now: Instant,
    ) -> Result<()> {
        self.remove(peer);
        self.prune(wall, now);
        ensure!(
            peer.len() <= 1024 && self.peers.len() < MAX_PEERS,
            "peer limit reached"
        );
        ensure!(
            request.purpose == "probe"
                && request.account_sid == "S-1-0-0"
                && request.account_name == "Authentication test",
            "only probe requests allowed"
        );
        ensure!(
            !json.is_empty() && json.len() <= MAX_MESSAGE,
            "invalid message size"
        );
        let expires = request.expires_at_ms;
        let pending = PendingApproval::new(request, wall)?;
        self.peers.insert(
            peer.into(),
            Peer {
                pending,
                json,
                offset: 0,
                transfer: Transfer::default(),
                created: wall,
                expires,
                deadline: now + Duration::from_millis(expires - wall),
            },
        );
        Ok(())
    }
    pub fn read(&mut self, peer: &str, wall: u64, now: Instant) -> Result<Vec<u8>> {
        self.prune(wall, now);
        let p = self
            .peers
            .get_mut(peer)
            .ok_or_else(|| anyhow::anyhow!("fresh control required"))?;
        ensure!(p.offset < p.json.len(), "request already transferred");
        let end = (p.offset + 16).min(p.json.len());
        let mut frame = Vec::with_capacity(20);
        frame.extend_from_slice(&(p.offset as u16).to_be_bytes());
        frame.extend_from_slice(&(p.json.len() as u16).to_be_bytes());
        frame.extend_from_slice(&p.json[p.offset..end]);
        p.offset = end;
        Ok(frame)
    }
    /// Called under the transport's single mutex: verification and consume are atomic.
    pub fn write(&mut self, peer: &str, frame: &[u8], wall: u64, now: Instant) -> Result<bool> {
        self.prune(wall, now);
        let result = (|| {
            let p = self
                .peers
                .get_mut(peer)
                .ok_or_else(|| anyhow::anyhow!("fresh control required"))?;
            ensure!(p.offset == p.json.len(), "request read incomplete");
            let Some(bytes) = p.transfer.push(frame)? else {
                return Ok(false);
            };
            let Some(key) = &self.key else {
                bail!("unpaired Watch: no enrolled public key");
            };
            let approval: SignedApproval = serde_json::from_slice(&bytes)?;
            p.pending.accept(&approval, key, wall)?;
            Ok(true)
        })();
        if result.is_err() || matches!(result, Ok(true)) {
            self.remove(peer);
        }
        result
    }
}
