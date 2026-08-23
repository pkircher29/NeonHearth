use chrono::{DateTime, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct IdentityConfig {
    pub auto_identification_threshold: f32,
    pub router_hint_cap: f32,
    pub match_threshold: f32,
    pub max_facts_per_device: usize,
    pub max_proposals: usize,
    pub max_devices: usize,
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
            max_facts_per_device: 256,
            max_proposals: 1024,
            max_devices: 4096,
            max_output_facts: 512,
            max_audit_records: 4096,
            max_key_len: 96,
            max_value_len: 1024,
            max_source_len: 128,
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum IdentityError {
    #[error("invalid confidence")]
    InvalidConfidence,
    #[error("invalid or oversized {0}")]
    InvalidInput(&'static str),
    #[error("capacity exceeded: {0}")]
    Capacity(&'static str),
    #[error("device not found")]
    DeviceNotFound,
    #[error("proposal not found or already decided")]
    ProposalNotFound,
    #[error("device id source exhausted")]
    IdSourceExhausted,
    #[error("decision cannot be undone")]
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

pub struct IdentityEngine {
    cfg: IdentityConfig,
    ids: Box<dyn Iterator<Item = DeviceId> + Send>,
    facts: HashMap<DeviceId, Vec<EvidenceFact>>,
    parent: HashMap<DeviceId, DeviceId>,
    proposals: Vec<MergeProposal>,
    audit: Vec<AuditRecord>,
    next_proposal: u64,
}

impl IdentityEngine {
    pub fn new<I: Iterator<Item = DeviceId> + Send + 'static>(cfg: IdentityConfig, ids: I) -> Self {
        Self {
            cfg,
            ids: Box::new(ids),
            facts: HashMap::new(),
            parent: HashMap::new(),
            proposals: vec![],
            audit: vec![],
            next_proposal: 1,
        }
    }
    pub fn observe(
        &mut self,
        device: Option<DeviceId>,
        facts: Vec<EvidenceFact>,
    ) -> Result<DeviceId, IdentityError> {
        self.observe_at(device, facts, Utc::now())
    }
    pub fn observe_at(
        &mut self,
        device: Option<DeviceId>,
        mut incoming: Vec<EvidenceFact>,
        now: DateTime<Utc>,
    ) -> Result<DeviceId, IdentityError> {
        self.prepare(&mut incoming)?;
        if let Some(id) = device {
            self.add_prepared(id, incoming)?;
            return Ok(id);
        }
        if incoming.len() > self.cfg.max_facts_per_device {
            return Err(IdentityError::Capacity("facts"));
        }
        let mut seen = HashSet::new();
        let mut roots: Vec<_> = self
            .facts
            .keys()
            .filter_map(|id| self.resolve(*id).ok())
            .filter(|id| seen.insert(*id))
            .collect();
        roots.sort_by_key(ToString::to_string);
        let mut matches: Vec<(DeviceId, Match)> = roots
            .into_iter()
            .filter_map(|id| {
                let existing = self.all_facts(id).ok()?;
                let m = match_facts(&existing, &incoming, now, self.cfg.match_threshold);
                (m.any).then_some((id, m))
            })
            .collect();
        matches.sort_by_key(|(id, _)| id.to_string());
        let eligible: Vec<_> = matches
            .iter()
            .filter(|(_, m)| m.auto)
            .map(|(id, _)| *id)
            .collect();
        if eligible.len() == 1 {
            let id = eligible[0];
            self.add_prepared(id, incoming)?;
            return Ok(id);
        }
        let id = self.allocate()?;
        self.add_prepared(id, incoming)?;
        if eligible.len() > 1 || matches.len() > 1 {
            for (candidate, m) in matches.into_iter().take(16) {
                self.propose_merge_internal(candidate, id, m.score, m.families, m.reasons)?;
            }
        }
        Ok(id)
    }
    fn allocate(&mut self) -> Result<DeviceId, IdentityError> {
        if self.facts.len() >= self.cfg.max_devices {
            return Err(IdentityError::Capacity("devices"));
        }
        let id = self.ids.next().ok_or(IdentityError::IdSourceExhausted)?;
        self.facts.insert(id, vec![]);
        self.parent.insert(id, id);
        Ok(id)
    }
    fn prepare(&self, facts: &mut [EvidenceFact]) -> Result<(), IdentityError> {
        for f in facts {
            if !f.confidence.is_finite() || !(0.0..=1.0).contains(&f.confidence) {
                return Err(IdentityError::InvalidConfidence);
            }
            if f.key.is_empty() || f.key.len() > self.cfg.max_key_len {
                return Err(IdentityError::InvalidInput("key"));
            }
            if f.value.is_empty() || f.value.len() > self.cfg.max_value_len {
                return Err(IdentityError::InvalidInput("value"));
            }
            if f.source.is_empty() || f.source.len() > self.cfg.max_source_len {
                return Err(IdentityError::InvalidInput("source"));
            }
            if f.family == EvidenceFamily::RouterHint {
                f.confidence = f.confidence.min(self.cfg.router_hint_cap);
            }
        }
        Ok(())
    }
    fn add_prepared(
        &mut self,
        id: DeviceId,
        facts: Vec<EvidenceFact>,
    ) -> Result<(), IdentityError> {
        let target = self
            .facts
            .get_mut(&id)
            .ok_or(IdentityError::DeviceNotFound)?;
        if target.len().saturating_add(facts.len()) > self.cfg.max_facts_per_device {
            return Err(IdentityError::Capacity("facts"));
        }
        target.extend(facts);
        Ok(())
    }
    pub fn add_facts(
        &mut self,
        id: DeviceId,
        mut facts: Vec<EvidenceFact>,
    ) -> Result<(), IdentityError> {
        self.prepare(&mut facts)?;
        self.add_prepared(id, facts)
    }
    pub fn facts(&self, id: DeviceId) -> Result<Vec<EvidenceFact>, IdentityError> {
        let mut out = self.all_facts(id)?;
        out.truncate(self.cfg.max_output_facts);
        Ok(out)
    }
    fn all_facts(&self, id: DeviceId) -> Result<Vec<EvidenceFact>, IdentityError> {
        let root = self.resolve(id)?;
        let mut out = vec![];
        for key in self.facts.keys() {
            if self.resolve(*key)? == root {
                out.extend(self.facts[key].clone())
            }
        }
        out.sort_by(|a, b| {
            (&a.key, &a.value, &a.source, a.observed_at).cmp(&(
                &b.key,
                &b.value,
                &b.source,
                b.observed_at,
            ))
        });
        Ok(out)
    }
    pub fn resolve(&self, mut id: DeviceId) -> Result<DeviceId, IdentityError> {
        if !self.parent.contains_key(&id) {
            return Err(IdentityError::DeviceNotFound);
        }
        for _ in 0..self.parent.len() {
            let p = self.parent[&id];
            if p == id {
                return Ok(id);
            }
            id = p
        }
        Err(IdentityError::InvalidInput("merge cycle"))
    }
    pub fn identification(&self, id: DeviceId) -> Result<Option<Identification>, IdentityError> {
        self.identification_at(id, Utc::now())
    }
    pub fn identification_at(
        &self,
        id: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<Option<Identification>, IdentityError> {
        let facts = self.all_facts(id)?;
        let active = |f: &&EvidenceFact| f.expires_at.is_none_or(|x| x > now);
        let pick = |key: &str| {
            facts
                .iter()
                .filter(active)
                .filter(|f| f.key == key)
                .max_by(|a, b| {
                    let ao = a.owner_confirmed || a.family == EvidenceFamily::Owner;
                    let bo = b.owner_confirmed || b.family == EvidenceFamily::Owner;
                    (ao, a.confidence.to_bits(), &a.value).cmp(&(
                        bo,
                        b.confidence.to_bits(),
                        &b.value,
                    ))
                })
        };
        let Some(vendor) = pick("vendor") else {
            return Ok(None);
        };
        let Some(class) = pick("class") else {
            return Ok(None);
        };
        let owner_vendor = vendor.owner_confirmed || vendor.family == EvidenceFamily::Owner;
        let owner_class = class.owner_confirmed || class.family == EvidenceFamily::Owner;
        let conflicts = |selected: &EvidenceFact| {
            !selected.owner_confirmed
                && selected.family != EvidenceFamily::Owner
                && facts.iter().filter(active).any(|f| {
                    f.key == selected.key
                        && f.value != selected.value
                        && f.family != EvidenceFamily::RouterHint
                        && f.confidence >= self.cfg.auto_identification_threshold
                })
        };
        if conflicts(vendor) || conflicts(class) {
            return Ok(None);
        }
        if (!owner_vendor && vendor.confidence < self.cfg.auto_identification_threshold)
            || (!owner_class && class.confidence < self.cfg.auto_identification_threshold)
        {
            return Ok(None);
        }
        let mut families: Vec<_> = facts
            .iter()
            .filter(active)
            .filter(|f| {
                ((f.key == "vendor" && f.value == vendor.value)
                    || (f.key == "class" && f.value == class.value))
                    && (f.confidence >= self.cfg.auto_identification_threshold
                        || f.owner_confirmed
                        || f.family == EvidenceFamily::Owner)
                    && f.family != EvidenceFamily::RouterHint
            })
            .map(|f| f.family)
            .collect();
        families.sort_by_key(|x| family_rank(*x));
        families.dedup();
        if families.len() < 2 && !(owner_vendor || owner_class) {
            return Ok(None);
        }
        Ok(Some(Identification {
            vendor: vendor.value.clone(),
            device_class: class.value.clone(),
            model: pick("model").map(|x| x.value.clone()),
            firmware: pick("firmware").map(|x| x.value.clone()),
            confidence: if owner_vendor || owner_class {
                1.0
            } else {
                vendor.confidence.min(class.confidence)
            },
            families,
        }))
    }
    pub fn clear_owner_fact(&mut self, id: DeviceId, key: &str) -> Result<(), IdentityError> {
        let root = self.resolve(id)?;
        let members: HashSet<_> = self
            .facts
            .keys()
            .copied()
            .filter(|candidate| self.resolve(*candidate).is_ok_and(|r| r == root))
            .collect();
        for (d, fs) in &mut self.facts {
            if members.contains(d) {
                fs.retain(|f| {
                    !(f.key == key && (f.owner_confirmed || f.family == EvidenceFamily::Owner))
                });
            }
        }
        Ok(())
    }
    pub fn propose_merge(
        &mut self,
        left: DeviceId,
        right: DeviceId,
        score: f32,
        families: Vec<EvidenceFamily>,
        reasons: Vec<String>,
    ) -> Result<ProposalId, IdentityError> {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(IdentityError::InvalidConfidence);
        }
        self.resolve(left)?;
        self.resolve(right)?;
        self.propose_merge_internal(left, right, score, families, reasons)
    }
    fn propose_merge_internal(
        &mut self,
        left: DeviceId,
        right: DeviceId,
        score: f32,
        mut families: Vec<EvidenceFamily>,
        mut reasons: Vec<String>,
    ) -> Result<ProposalId, IdentityError> {
        if self.proposals.len() >= self.cfg.max_proposals {
            return Err(IdentityError::Capacity("proposals"));
        }
        if reasons.len() > 16 || reasons.iter().any(|x| x.len() > 256) {
            return Err(IdentityError::InvalidInput("reasons"));
        }
        families.sort_by_key(|x| family_rank(*x));
        families.dedup();
        reasons.sort();
        reasons.dedup();
        let id = self.next_proposal;
        self.next_proposal += 1;
        self.proposals.push(MergeProposal {
            id,
            left,
            right,
            score,
            families,
            reasons,
            status: ProposalStatus::Pending,
        });
        Ok(id)
    }
    pub fn proposals(&self) -> &[MergeProposal] {
        &self.proposals
    }
    pub fn audit(&self) -> &[AuditRecord] {
        &self.audit
    }
    pub fn decide(&mut self, id: ProposalId, decision: Decision) -> Result<(), IdentityError> {
        if self.audit.len() >= self.cfg.max_audit_records {
            return Err(IdentityError::Capacity("audit"));
        }
        let pos = self
            .proposals
            .iter()
            .position(|p| p.id == id && p.status == ProposalStatus::Pending)
            .ok_or(IdentityError::ProposalNotFound)?;
        let status = match decision {
            Decision::Accept => ProposalStatus::Accepted,
            Decision::Reject => ProposalStatus::Rejected,
        };
        if decision == Decision::Accept {
            let l = self.resolve(self.proposals[pos].left)?;
            let r = self.resolve(self.proposals[pos].right)?;
            if l != r {
                self.parent.insert(r, l);
            }
        }
        self.proposals[pos].status = status;
        self.audit.push(AuditRecord {
            proposal_id: id,
            action: status,
        });
        Ok(())
    }
    pub fn undo(&mut self, id: ProposalId) -> Result<(), IdentityError> {
        if self.audit.len() >= self.cfg.max_audit_records {
            return Err(IdentityError::Capacity("audit"));
        }
        let pos = self
            .proposals
            .iter()
            .position(|p| p.id == id && p.status == ProposalStatus::Accepted)
            .ok_or(IdentityError::CannotUndo)?;
        let right = self.proposals[pos].right;
        self.parent.insert(right, right);
        self.proposals[pos].status = ProposalStatus::Undone;
        self.audit.push(AuditRecord {
            proposal_id: id,
            action: ProposalStatus::Undone,
        });
        Ok(())
    }
}

#[derive(Default)]
struct Match {
    any: bool,
    auto: bool,
    score: f32,
    families: Vec<EvidenceFamily>,
    reasons: Vec<String>,
}
fn match_facts(
    old: &[EvidenceFact],
    new: &[EvidenceFact],
    now: DateTime<Utc>,
    threshold: f32,
) -> Match {
    let active = |f: &&EvidenceFact| {
        f.expires_at.is_none_or(|x| x > now)
            && f.family != EvidenceFamily::RouterHint
            && !f.owner_confirmed
    };
    let old: Vec<_> = old.iter().filter(active).collect();
    let new: Vec<_> = new.iter().filter(active).collect();
    let contradiction = old.iter().any(|a| {
        new.iter().any(|b| {
            a.key == b.key
                && a.value != b.value
                && a.confidence >= 0.9
                && b.confidence >= 0.9
                && strong_key(&a.key)
                && !(a.key == "mac" && private_mac(&a.value) && private_mac(&b.value))
        })
    });
    let mut fam = HashSet::new();
    let mut reasons = vec![];
    let mut best = 0f32;
    let mut stable_mac = false;
    for a in &old {
        for b in &new {
            if a.key == b.key && a.value == b.value && identity_key(&a.key) {
                let strength = a.confidence.min(b.confidence);
                best = best.max(strength);
                if strength >= threshold && eligible_family(a.family) && eligible_family(b.family) {
                    fam.insert(family_rank(a.family));
                    reasons.push(format!("{} matched", a.key));
                }
                if strength >= threshold && a.key == "mac" && !private_mac(&a.value) {
                    stable_mac = true;
                }
            }
        }
    }
    let mut families: Vec<_> = fam.into_iter().filter_map(rank_family).collect();
    families.sort_by_key(|x| family_rank(*x));
    let auto = !contradiction && (stable_mac || families.len() >= 2);
    Match {
        any: !reasons.is_empty(),
        auto,
        score: if contradiction { best * 0.25 } else { best },
        families,
        reasons,
    }
}
fn eligible_family(f: EvidenceFamily) -> bool {
    !matches!(
        f,
        EvidenceFamily::Addressing | EvidenceFamily::RouterHint | EvidenceFamily::Owner
    )
}
fn identity_key(k: &str) -> bool {
    matches!(
        k,
        "mac"
            | "serial"
            | "uuid"
            | "onvif_uuid"
            | "tls_spki"
            | "ssh_host_key"
            | "upnp_udn"
            | "dhcp_client_id"
            | "client_id"
            | "duid"
    )
}
fn strong_key(k: &str) -> bool {
    matches!(
        k,
        "mac" | "serial" | "uuid" | "onvif_uuid" | "tls_spki" | "ssh_host_key"
    )
}
fn private_mac(v: &str) -> bool {
    v.split(':')
        .next()
        .and_then(|x| u8::from_str_radix(x, 16).ok())
        .is_some_and(|x| x & 2 != 0)
}
fn family_rank(f: EvidenceFamily) -> u8 {
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
fn rank_family(x: u8) -> Option<EvidenceFamily> {
    Some(match x {
        0 => EvidenceFamily::LinkLayer,
        1 => EvidenceFamily::Addressing,
        2 => EvidenceFamily::Naming,
        3 => EvidenceFamily::Service,
        4 => EvidenceFamily::Cryptographic,
        5 => EvidenceFamily::RouterHint,
        6 => EvidenceFamily::Owner,
        _ => return None,
    })
}
