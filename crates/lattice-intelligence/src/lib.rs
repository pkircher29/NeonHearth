use chrono::{DateTime, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct IdentityConfig {
    pub auto_identification_threshold: f32,
    pub router_hint_cap: f32,
    pub match_threshold: f32,
    pub contradiction_threshold: f32,
    pub max_facts_per_device: usize,
    pub max_proposals: usize,
    pub max_devices: usize,
    pub max_merge_edges: usize,
    pub max_candidate_work: usize,
    pub max_output_facts: usize,
    pub max_audit_records: usize,
    pub max_key_len: usize,
    pub max_value_len: usize,
    pub max_source_len: usize,
}
impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            auto_identification_threshold: 0.85,
            router_hint_cap: 0.49,
            match_threshold: 0.85,
            contradiction_threshold: 0.85,
            max_facts_per_device: 256,
            max_proposals: 1024,
            max_devices: 4096,
            max_merge_edges: 4096,
            max_candidate_work: 1_000_000,
            max_output_facts: 512,
            max_audit_records: 4096,
            max_key_len: 96,
            max_value_len: 1024,
            max_source_len: 128,
        }
    }
}
impl IdentityConfig {
    fn valid(&self) -> Result<(), IdentityError> {
        for n in [
            self.auto_identification_threshold,
            self.router_hint_cap,
            self.match_threshold,
            self.contradiction_threshold,
        ] {
            if !n.is_finite() || !(0.0..=1.0).contains(&n) {
                return Err(IdentityError::InvalidConfig("confidence"));
            }
        }
        if self.auto_identification_threshold < 0.85
            || self.router_hint_cap >= 0.85
            || self.match_threshold < 0.85
            || self.contradiction_threshold < 0.85
        {
            return Err(IdentityError::InvalidConfig("unsafe thresholds"));
        }
        if [
            self.max_facts_per_device,
            self.max_proposals,
            self.max_devices,
            self.max_merge_edges,
            self.max_candidate_work,
            self.max_output_facts,
            self.max_audit_records,
            self.max_key_len,
            self.max_value_len,
            self.max_source_len,
        ]
        .contains(&0)
        {
            return Err(IdentityError::InvalidConfig("zero capacity"));
        }
        Ok(())
    }
}
#[derive(Debug, Error, PartialEq)]
pub enum IdentityError {
    #[error("invalid confidence")]
    InvalidConfidence,
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("capacity: {0}")]
    Capacity(&'static str),
    #[error("device not found")]
    DeviceNotFound,
    #[error("proposal not found")]
    ProposalNotFound,
    #[error("id source exhausted")]
    IdSourceExhausted,
    #[error("cannot undo")]
    CannotUndo,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identification {
    pub vendor: String,
    pub device_class: String,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub confidence: f32,
    pub families: Vec<EvidenceFamily>,
}
pub type ProposalId = u64;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MergeProposal {
    pub id: ProposalId,
    pub left: DeviceId,
    pub right: DeviceId,
    pub score: f32,
    pub families: Vec<EvidenceFamily>,
    pub reasons: Vec<String>,
    pub status: ProposalStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Pending,
    Accepted,
    Rejected,
    Undone,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Decision {
    Accept,
    Reject,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub proposal_id: ProposalId,
    pub action: ProposalStatus,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OwnerAuditRecord {
    pub sequence: u64,
    pub device_id: DeviceId,
    pub key: String,
    pub value: Option<String>,
    pub recorded_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub devices: usize,
    pub facts: usize,
    pub proposals: usize,
    pub audit: usize,
    pub owner_audit: usize,
    pub edges: usize,
    pub next_proposal: u64,
}
#[derive(Clone)]
struct Edge {
    a: DeviceId,
    b: DeviceId,
    active: bool,
}
pub struct IdentityEngine {
    cfg: IdentityConfig,
    ids: VecDeque<DeviceId>,
    facts: HashMap<DeviceId, Vec<EvidenceFact>>,
    proposals: Vec<MergeProposal>,
    edges: HashMap<u64, Edge>,
    audit: Vec<AuditRecord>,
    owners: Vec<OwnerAuditRecord>,
    next_proposal: u64,
    next_owner: u64,
}

impl IdentityEngine {
    pub fn new<I: Iterator<Item = DeviceId> + Send>(
        cfg: IdentityConfig,
        ids: I,
    ) -> Result<Self, IdentityError> {
        cfg.valid()?;
        let max_devices = cfg.max_devices;
        Ok(Self {
            cfg,
            ids: ids.take(max_devices).collect(),
            facts: HashMap::new(),
            proposals: vec![],
            edges: HashMap::new(),
            audit: vec![],
            owners: vec![],
            next_proposal: 1,
            next_owner: 1,
        })
    }
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            devices: self.facts.len(),
            facts: self.facts.values().map(Vec::len).sum(),
            proposals: self.proposals.len(),
            audit: self.audit.len(),
            owner_audit: self.owners.len(),
            edges: self.edges.values().filter(|x| x.active).count(),
            next_proposal: self.next_proposal,
        }
    }
    pub fn observe(
        &mut self,
        id: Option<DeviceId>,
        f: Vec<EvidenceFact>,
    ) -> Result<DeviceId, IdentityError> {
        self.observe_at(id, f, Utc::now())
    }
    pub fn observe_at(
        &mut self,
        id: Option<DeviceId>,
        mut incoming: Vec<EvidenceFact>,
        now: DateTime<Utc>,
    ) -> Result<DeviceId, IdentityError> {
        self.prepare(&mut incoming)?;
        if let Some(alias) = id {
            let root = self.resolve(alias)?;
            self.preadd(alias, incoming.len())?;
            self.facts
                .get_mut(&alias)
                .ok_or(IdentityError::DeviceNotFound)?
                .extend(incoming);
            return Ok(root);
        }
        if incoming.len() > self.cfg.max_facts_per_device
            || self.facts.len() >= self.cfg.max_devices
        {
            return Err(IdentityError::Capacity("devices or facts"));
        }
        let comps = self.components()?;
        let mut work = 0usize;
        let mut matches = vec![];
        for c in comps {
            let refs = self.refs(&c)?;
            work = work
                .checked_add(
                    refs.len()
                        .checked_mul(incoming.len())
                        .ok_or(IdentityError::Capacity("work"))?,
                )
                .ok_or(IdentityError::Capacity("work"))?;
            if work > self.cfg.max_candidate_work {
                return Err(IdentityError::Capacity("work"));
            }
            let m = matching(&refs, &incoming, now, &self.cfg);
            if m.any {
                matches.push((canon(&c), m))
            }
        }
        matches.sort_by_key(|x| x.0.to_string());
        if matches.len() == 1 && matches[0].1.auto {
            let root = matches[0].0;
            self.preadd(root, incoming.len())?;
            self.facts
                .get_mut(&root)
                .ok_or(IdentityError::DeviceNotFound)?
                .extend(incoming);
            return Ok(root);
        }
        self.preprops(matches.len())?;
        let fresh = *self.ids.front().ok_or(IdentityError::IdSourceExhausted)?;
        if self.facts.contains_key(&fresh) {
            return Err(IdentityError::InvalidInput("duplicate id"));
        }
        self.ids.pop_front();
        self.facts.insert(fresh, incoming);
        for (other, m) in matches {
            self.insert_prop(other, fresh, m.score, m.families, m.reasons);
        }
        Ok(fresh)
    }
    fn prepare(&self, fs: &mut [EvidenceFact]) -> Result<(), IdentityError> {
        for f in fs {
            if !f.confidence.is_finite() || !(0.0..=1.0).contains(&f.confidence) {
                return Err(IdentityError::InvalidConfidence);
            }
            if f.owner_confirmed || f.family == EvidenceFamily::Owner {
                return Err(IdentityError::InvalidInput("owner provenance"));
            }
            if f.key.is_empty()
                || f.key.len() > self.cfg.max_key_len
                || f.value.is_empty()
                || f.value.len() > self.cfg.max_value_len
                || f.source.is_empty()
                || f.source.len() > self.cfg.max_source_len
            {
                return Err(IdentityError::InvalidInput("field bounds"));
            }
            if !allowed(&f.key, f.family) {
                return Err(IdentityError::InvalidInput("taxonomy"));
            }
            if f.key == "mac" {
                f.value = mac(&f.value)?
            }
            if f.family == EvidenceFamily::RouterHint {
                f.confidence = f.confidence.min(self.cfg.router_hint_cap)
            }
        }
        Ok(())
    }
    fn preadd(&self, id: DeviceId, n: usize) -> Result<(), IdentityError> {
        let c = self.component(id)?;
        let count: usize = c.iter().map(|d| self.facts[d].len()).sum();
        if count + n > self.cfg.max_facts_per_device {
            return Err(IdentityError::Capacity("facts"));
        }
        Ok(())
    }
    pub fn add_facts(
        &mut self,
        id: DeviceId,
        mut fs: Vec<EvidenceFact>,
    ) -> Result<(), IdentityError> {
        self.prepare(&mut fs)?;
        self.preadd(id, fs.len())?;
        self.facts
            .get_mut(&id)
            .ok_or(IdentityError::DeviceNotFound)?
            .extend(fs);
        Ok(())
    }
    pub fn resolve(&self, id: DeviceId) -> Result<DeviceId, IdentityError> {
        Ok(canon(&self.component(id)?))
    }
    fn component(&self, id: DeviceId) -> Result<Vec<DeviceId>, IdentityError> {
        if !self.facts.contains_key(&id) {
            return Err(IdentityError::DeviceNotFound);
        }
        if self.facts.len().saturating_mul(self.edges.len().max(1)) > self.cfg.max_candidate_work {
            return Err(IdentityError::Capacity("graph work"));
        }
        let mut seen = HashSet::from([id]);
        let mut q = VecDeque::from([id]);
        while let Some(x) = q.pop_front() {
            for e in self.edges.values().filter(|e| e.active) {
                let y = if e.a == x {
                    Some(e.b)
                } else if e.b == x {
                    Some(e.a)
                } else {
                    None
                };
                if let Some(y) = y
                    && seen.insert(y)
                {
                    q.push_back(y)
                }
            }
        }
        let mut v: Vec<_> = seen.into_iter().collect();
        v.sort_by_key(ToString::to_string);
        Ok(v)
    }
    fn components(&self) -> Result<Vec<Vec<DeviceId>>, IdentityError> {
        if self.edges.len() > self.cfg.max_merge_edges {
            return Err(IdentityError::Capacity("graph"));
        }
        let mut ids: Vec<_> = self.facts.keys().copied().collect();
        ids.sort_by_key(ToString::to_string);
        let mut seen: HashSet<DeviceId> = HashSet::new();
        let mut out = vec![];
        for id in ids {
            if !seen.contains(&id) {
                let c = self.component(id)?;
                seen.extend(c.iter().copied());
                out.push(c)
            }
        }
        Ok(out)
    }
    fn refs<'a>(&'a self, c: &[DeviceId]) -> Result<Vec<&'a EvidenceFact>, IdentityError> {
        let n: usize = c.iter().map(|d| self.facts[d].len()).sum();
        if n > self.cfg.max_candidate_work {
            return Err(IdentityError::Capacity("work"));
        }
        let mut v = Vec::with_capacity(n);
        for d in c {
            v.extend(self.facts[d].iter())
        }
        Ok(v)
    }
    pub fn facts(&self, id: DeviceId) -> Result<Vec<EvidenceFact>, IdentityError> {
        let c = self.component(id)?;
        let n: usize = c.iter().map(|d| self.facts[d].len()).sum();
        if n > self.cfg.max_output_facts {
            return Err(IdentityError::Capacity("output"));
        }
        let mut v = vec![];
        for d in c {
            for f in &self.facts[&d] {
                v.push((d, f))
            }
        }
        v.sort_by(|a, b| order(a.0, a.1, b.0, b.1));
        Ok(v.into_iter().map(|x| x.1.clone()).collect())
    }
    pub fn identification(&self, id: DeviceId) -> Result<Option<Identification>, IdentityError> {
        self.identification_at(id, Utc::now())
    }
    pub fn identification_at(
        &self,
        id: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<Option<Identification>, IdentityError> {
        let c = self.component(id)?;
        let refs = self.refs(&c)?;
        let active: Vec<_> = refs
            .into_iter()
            .filter(|f| {
                f.expires_at.is_none_or(|x| x > now) && f.family != EvidenceFamily::RouterHint
            })
            .collect();
        let own = |k: &str| {
            self.owners
                .iter()
                .rev()
                .find(|o| c.contains(&o.device_id) && o.key == k)
        };
        let pick = |k: &str| {
            active
                .iter()
                .copied()
                .filter(|f| f.key == k)
                .max_by(|a, b| {
                    a.confidence
                        .total_cmp(&b.confidence)
                        .then(a.value.cmp(&b.value))
                })
        };
        let ov = own("vendor").filter(|x| x.value.is_some());
        let oc = own("class").filter(|x| x.value.is_some());
        let vendor = ov
            .and_then(|x| x.value.as_deref())
            .or_else(|| pick("vendor").map(|x| x.value.as_str()));
        let class = oc
            .and_then(|x| x.value.as_deref())
            .or_else(|| pick("class").map(|x| x.value.as_str()));
        let (Some(vendor), Some(class)) = (vendor, class) else {
            return Ok(None);
        };
        let av = pick("vendor");
        let ac = pick("class");
        if ov.is_none() && av.is_none_or(|x| x.confidence < self.cfg.auto_identification_threshold)
            || oc.is_none()
                && ac.is_none_or(|x| x.confidence < self.cfg.auto_identification_threshold)
        {
            return Ok(None);
        }
        for (k, val, owned) in [
            ("vendor", vendor, ov.is_some()),
            ("class", class, oc.is_some()),
        ] {
            if !owned
                && active.iter().any(|f| {
                    f.key == k
                        && f.value != val
                        && f.confidence >= self.cfg.auto_identification_threshold
                })
            {
                return Ok(None);
            }
        }
        let mut fam: Vec<_> = active
            .iter()
            .filter(|f| {
                ((f.key == "vendor" && f.value == vendor) || (f.key == "class" && f.value == class))
                    && f.confidence >= self.cfg.auto_identification_threshold
            })
            .map(|x| x.family)
            .collect();
        sortfam(&mut fam);
        if (ov.is_none() || oc.is_none()) && fam.len() < 2 {
            return Ok(None);
        }
        Ok(Some(Identification {
            vendor: vendor.into(),
            device_class: class.into(),
            model: own("model")
                .filter(|x| x.value.is_some())
                .and_then(|x| x.value.clone())
                .or_else(|| pick("model").map(|x| x.value.clone())),
            firmware: own("firmware")
                .filter(|x| x.value.is_some())
                .and_then(|x| x.value.clone())
                .or_else(|| pick("firmware").map(|x| x.value.clone())),
            confidence: if ov.is_some() && oc.is_some() {
                1.0
            } else {
                av.map_or(1., |x| x.confidence)
                    .min(ac.map_or(1., |x| x.confidence))
            },
            families: fam,
        }))
    }
    pub fn set_owner_fact(
        &mut self,
        id: DeviceId,
        key: &str,
        value: &str,
        at: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        self.owner(id, key, Some(value), at)
    }
    pub fn clear_owner_fact(&mut self, id: DeviceId, key: &str) -> Result<(), IdentityError> {
        self.clear_owner_fact_at(id, key, Utc::now())
    }
    pub fn clear_owner_fact_at(
        &mut self,
        id: DeviceId,
        key: &str,
        at: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        self.owner(id, key, None, at)
    }
    fn owner(
        &mut self,
        id: DeviceId,
        key: &str,
        value: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        let root = self.resolve(id)?;
        if !matches!(
            key,
            "vendor" | "class" | "model" | "firmware" | "name" | "room"
        ) || value.is_some_and(|x| x.is_empty() || x.len() > self.cfg.max_value_len)
        {
            return Err(IdentityError::InvalidInput("owner fact"));
        }
        if self.owners.len() >= self.cfg.max_audit_records {
            return Err(IdentityError::Capacity("owner audit"));
        }
        let seq = self.next_owner;
        let next = seq
            .checked_add(1)
            .ok_or(IdentityError::Capacity("owner sequence"))?;
        self.owners.push(OwnerAuditRecord {
            sequence: seq,
            device_id: root,
            key: key.into(),
            value: value.map(str::to_owned),
            recorded_at: at,
        });
        self.next_owner = next;
        Ok(())
    }
    pub fn owner_audit(&self) -> &[OwnerAuditRecord] {
        &self.owners
    }
    pub fn propose_merge(
        &mut self,
        a: DeviceId,
        b: DeviceId,
        score: f32,
        families: Vec<EvidenceFamily>,
        reasons: Vec<String>,
    ) -> Result<u64, IdentityError> {
        self.resolve(a)?;
        self.resolve(b)?;
        validprop(score, &families, &reasons)?;
        self.preprops(1)?;
        Ok(self.insert_prop(a, b, score, families, reasons))
    }
    fn preprops(&self, n: usize) -> Result<(), IdentityError> {
        if self
            .proposals
            .len()
            .checked_add(n)
            .is_none_or(|x| x > self.cfg.max_proposals)
            || n > 0 && self.next_proposal.checked_add(n as u64).is_none()
        {
            return Err(IdentityError::Capacity("proposals"));
        }
        Ok(())
    }
    fn insert_prop(
        &mut self,
        a: DeviceId,
        b: DeviceId,
        score: f32,
        mut families: Vec<EvidenceFamily>,
        mut reasons: Vec<String>,
    ) -> u64 {
        sortfam(&mut families);
        reasons.sort();
        reasons.dedup();
        let id = self.next_proposal;
        self.next_proposal += 1;
        self.proposals.push(MergeProposal {
            id,
            left: a,
            right: b,
            score,
            families,
            reasons,
            status: ProposalStatus::Pending,
        });
        id
    }
    pub fn proposals(&self) -> &[MergeProposal] {
        &self.proposals
    }
    pub fn audit(&self) -> &[AuditRecord] {
        &self.audit
    }
    pub fn decide(&mut self, id: u64, d: Decision) -> Result<(), IdentityError> {
        if self.audit.len() >= self.cfg.max_audit_records {
            return Err(IdentityError::Capacity("audit"));
        }
        let p = self
            .proposals
            .iter()
            .position(|p| p.id == id && p.status == ProposalStatus::Pending)
            .ok_or(IdentityError::ProposalNotFound)?;
        let status = if d == Decision::Accept {
            ProposalStatus::Accepted
        } else {
            ProposalStatus::Rejected
        };
        if d == Decision::Accept {
            if self.edges.len() >= self.cfg.max_merge_edges {
                return Err(IdentityError::Capacity("edges"));
            }
            self.edges.insert(
                id,
                Edge {
                    a: self.proposals[p].left,
                    b: self.proposals[p].right,
                    active: true,
                },
            );
        }
        self.proposals[p].status = status;
        self.audit.push(AuditRecord {
            proposal_id: id,
            action: status,
        });
        Ok(())
    }
    pub fn undo(&mut self, id: u64) -> Result<(), IdentityError> {
        if self.audit.len() >= self.cfg.max_audit_records {
            return Err(IdentityError::Capacity("audit"));
        }
        let p = self
            .proposals
            .iter()
            .position(|p| p.id == id && p.status == ProposalStatus::Accepted)
            .ok_or(IdentityError::CannotUndo)?;
        if let Some(e) = self.edges.get_mut(&id) {
            debug_assert!(e.active);
            e.active = false
        }
        self.proposals[p].status = ProposalStatus::Undone;
        self.audit.push(AuditRecord {
            proposal_id: id,
            action: ProposalStatus::Undone,
        });
        Ok(())
    }
}
struct Match {
    any: bool,
    auto: bool,
    score: f32,
    families: Vec<EvidenceFamily>,
    reasons: Vec<String>,
}
fn matching(
    old: &[&EvidenceFact],
    new: &[EvidenceFact],
    now: DateTime<Utc>,
    c: &IdentityConfig,
) -> Match {
    let live = |f: &EvidenceFact| {
        f.expires_at.is_none_or(|x| x > now) && f.family != EvidenceFamily::RouterHint
    };
    let (mut fam, mut why, mut score, mut conflict) = (vec![], vec![], 0f32, false);
    for a in old.iter().copied().filter(|x| live(x)) {
        for b in new.iter().filter(|x| live(x)) {
            if anchor(&a.key) == Some(a.family) && a.key == b.key && a.family == b.family {
                if a.value == b.value {
                    let s = a.confidence.min(b.confidence);
                    score = score.max(s);
                    if s >= c.match_threshold {
                        fam.push(a.family)
                    }
                    why.push(format!("{} matched", a.key))
                } else if !(a.key == "mac" && local_mac(&a.value) && local_mac(&b.value))
                    && a.confidence >= c.contradiction_threshold
                    && b.confidence >= c.contradiction_threshold
                {
                    conflict = true
                }
            }
        }
    }
    sortfam(&mut fam);
    why.sort();
    why.dedup();
    Match {
        any: !why.is_empty(),
        auto: !conflict && fam.len() >= 2,
        score: if conflict { score * 0.25 } else { score },
        families: fam,
        reasons: why,
    }
}
fn mac(v: &str) -> Result<String, IdentityError> {
    let valid = if v.contains(':') {
        v.split(':').count() == 6 && v.split(':').all(|x| x.len() == 2)
    } else if v.contains('-') {
        v.split('-').count() == 6 && v.split('-').all(|x| x.len() == 2)
    } else if v.contains('.') {
        v.split('.').count() == 3 && v.split('.').all(|x| x.len() == 4)
    } else {
        false
    };
    if !valid {
        return Err(IdentityError::InvalidInput("mac"));
    }
    let h: String = v
        .chars()
        .filter(|x| !matches!(x, ':' | '-' | '.'))
        .collect();
    if h.len() != 12 || !h.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err(IdentityError::InvalidInput("mac"));
    }
    let mut b = [0; 6];
    for i in 0..6 {
        b[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
            .map_err(|_| IdentityError::InvalidInput("mac"))?
    }
    if b[0] & 1 != 0 || b.iter().all(|x| *x == 0) {
        return Err(IdentityError::InvalidInput("multicast mac"));
    }
    Ok(b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}
fn local_mac(v: &str) -> bool {
    u8::from_str_radix(v.get(..2).unwrap_or(""), 16).is_ok_and(|x| x & 2 != 0)
}
fn allowed(k: &str, f: EvidenceFamily) -> bool {
    if f == EvidenceFamily::RouterHint {
        return matches!(
            k,
            "vendor" | "class" | "model" | "firmware" | "label" | "hostname" | "room"
        );
    }
    match k {
        "mac" => f == EvidenceFamily::LinkLayer,
        "ip" | "client_id" | "dhcp_client_id" | "duid" => f == EvidenceFamily::Addressing,
        "hostname" | "name" => f == EvidenceFamily::Naming,
        "tls_spki" | "ssh_host_key" => f == EvidenceFamily::Cryptographic,
        "serial" | "uuid" | "onvif_uuid" | "upnp_udn" => f == EvidenceFamily::Service,
        "vendor" | "class" | "model" | "firmware" => matches!(
            f,
            EvidenceFamily::Naming | EvidenceFamily::Service | EvidenceFamily::Cryptographic
        ),
        _ => false,
    }
}
fn anchor(k: &str) -> Option<EvidenceFamily> {
    Some(match k {
        "mac" => EvidenceFamily::LinkLayer,
        "client_id" | "dhcp_client_id" | "duid" => EvidenceFamily::Addressing,
        "tls_spki" | "ssh_host_key" => EvidenceFamily::Cryptographic,
        "serial" | "uuid" | "onvif_uuid" | "upnp_udn" => EvidenceFamily::Service,
        _ => return None,
    })
}
fn validprop(s: f32, f: &[EvidenceFamily], r: &[String]) -> Result<(), IdentityError> {
    if !s.is_finite() || !(0.0..=1.).contains(&s) {
        return Err(IdentityError::InvalidConfidence);
    }
    if f.is_empty()
        || f.len() > 7
        || f.iter()
            .any(|x| matches!(x, EvidenceFamily::RouterHint | EvidenceFamily::Owner))
    {
        return Err(IdentityError::InvalidInput("proposal families"));
    }
    if r.is_empty() || r.len() > 16 || r.iter().any(|x| x.is_empty() || x.len() > 256) {
        return Err(IdentityError::InvalidInput("reasons"));
    }
    Ok(())
}
fn rank(f: EvidenceFamily) -> u8 {
    match f {
        EvidenceFamily::LinkLayer => 0,
        EvidenceFamily::Addressing => 1,
        EvidenceFamily::Naming => 2,
        EvidenceFamily::Service => 3,
        EvidenceFamily::Cryptographic => 4,
        EvidenceFamily::RouterHint => 5,
        EvidenceFamily::Owner => 6,
    }
}
fn sortfam(v: &mut Vec<EvidenceFamily>) {
    v.sort_by_key(|x| rank(*x));
    v.dedup()
}
fn canon(v: &[DeviceId]) -> DeviceId {
    *v.iter()
        .min_by_key(|x| x.to_string())
        .expect("validated nonempty component")
}
fn order(da: DeviceId, a: &EvidenceFact, db: DeviceId, b: &EvidenceFact) -> std::cmp::Ordering {
    (
        da.to_string(),
        rank(a.family),
        &a.key,
        &a.value,
        &a.source,
        a.confidence.to_bits(),
        a.observed_at,
        a.expires_at,
        a.owner_confirmed,
    )
        .cmp(&(
            db.to_string(),
            rank(b.family),
            &b.key,
            &b.value,
            &b.source,
            b.confidence.to_bits(),
            b.observed_at,
            b.expires_at,
            b.owner_confirmed,
        ))
}
