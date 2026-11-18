//! One request per circuit this crate proves: the body in the prover's wire
//! format and what a backend needs to prove it. The
//! [`ProverExt`](super::ProverExt) trait, [`AsyncProverClient`](super::AsyncProverClient) and
//! [`SprClient`](crate::SprClient) all build their requests here, so each
//! circuit is described once.

use std::borrow::Cow;
use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        client::{Delivery, LocalProvingInputs, ProveRequest},
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_ring, to_json_ring,
            to_json_ring_authority,
        },
        proving_key::ExpectedProvingKey,
        transact::confidential_eddsa::ConfidentialEddsaTransferInputs,
    },
};

/// The assembled native inputs, or an encoded request for a server-only circuit.
enum Source<'a> {
    Transfer(TransferKind, Cow<'a, TransferInputs>),
    Merge(MergeKind, Cow<'a, MergeInputs>),
    Wire(Zeroizing<String>),
}

#[derive(Clone, Copy)]
enum TransferKind {
    Confidential,
    Ring,
    RingAuthority,
}

#[derive(Clone, Copy)]
enum MergeKind {
    Confidential,
    Ring,
}

pub(crate) struct CircuitRequest<'a> {
    source: Source<'a>,
    proving_key: ExpectedProvingKey,
    delivery: Delivery,
}

impl CircuitRequest<'_> {
    /// Send a borrowed request to a background blocking task.
    pub(crate) fn into_owned(self) -> CircuitRequest<'static> {
        let source = match self.source {
            Source::Transfer(kind, inputs) => {
                Source::Transfer(kind, Cow::Owned(inputs.into_owned()))
            }
            Source::Merge(kind, inputs) => Source::Merge(kind, Cow::Owned(inputs.into_owned())),
            Source::Wire(body) => Source::Wire(body),
        };
        CircuitRequest {
            source,
            proving_key: self.proving_key,
            delivery: self.delivery,
        }
    }
}

impl ProveRequest for CircuitRequest<'_> {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let body = match &self.source {
            Source::Transfer(TransferKind::Confidential, inputs) => to_json(inputs)?,
            Source::Transfer(TransferKind::Ring, inputs) => to_json_ring(inputs)?,
            Source::Transfer(TransferKind::RingAuthority, inputs) => {
                to_json_ring_authority(inputs)?
            }
            Source::Merge(MergeKind::Confidential, inputs) => to_json_merge(inputs),
            Source::Merge(MergeKind::Ring, inputs) => to_json_merge_ring(inputs),
            Source::Wire(body) => return Ok(body.clone()),
        };
        Ok(Zeroizing::new(body))
    }

    fn local_inputs(&self) -> Option<LocalProvingInputs<'_>> {
        Some(match &self.source {
            Source::Transfer(TransferKind::Confidential, inputs) => {
                LocalProvingInputs::Transfer(inputs)
            }
            Source::Transfer(TransferKind::Ring, inputs) => {
                LocalProvingInputs::TransferRing(inputs)
            }
            Source::Transfer(TransferKind::RingAuthority, inputs) => {
                LocalProvingInputs::RingAuthority(inputs)
            }
            Source::Merge(MergeKind::Confidential, inputs) => LocalProvingInputs::Merge(inputs),
            Source::Merge(MergeKind::Ring, inputs) => LocalProvingInputs::MergeRing(inputs),
            Source::Wire(_) => return None,
        })
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.proving_key.clone())
    }

    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

/// Transfer-shaped proofs are fast enough to ask for in the response.
fn in_response(source: Source<'_>, proving_key: ExpectedProvingKey) -> CircuitRequest<'_> {
    CircuitRequest {
        source,
        proving_key,
        delivery: Delivery::InResponse,
    }
}

fn transfer_request(
    kind: TransferKind,
    inputs: &TransferInputs,
    key: ExpectedProvingKey,
) -> Result<CircuitRequest<'_>, ClientError> {
    if let Some(index) = inputs
        .inputs
        .iter()
        .position(|input| input.nullifier_secret.is_none())
    {
        return Err(ClientError::MissingNullifierSecret { index });
    }
    Ok(in_response(
        Source::Transfer(kind, Cow::Borrowed(inputs)),
        key,
    ))
}

pub(crate) fn transfer(inputs: &TransferInputs) -> Result<CircuitRequest<'_>, ClientError> {
    let key = ExpectedProvingKey::transfer_confidential(inputs.inputs.len(), inputs.outputs.len())?;
    transfer_request(TransferKind::Confidential, inputs, key)
}

pub(crate) fn transfer_confidential_eddsa(
    inputs: &ConfidentialEddsaTransferInputs,
) -> Result<CircuitRequest<'static>, ClientError> {
    Ok(CircuitRequest {
        source: Source::Wire(inputs.body()?),
        proving_key: inputs.proving_key()?,
        delivery: inputs.delivery(),
    })
}

pub(crate) fn transfer_ring(inputs: &TransferInputs) -> Result<CircuitRequest<'_>, ClientError> {
    let key = ExpectedProvingKey::transfer_ring(inputs.inputs.len(), inputs.outputs.len())?;
    transfer_request(TransferKind::Ring, inputs, key)
}

pub(crate) fn ring_authority(inputs: &TransferInputs) -> Result<CircuitRequest<'_>, ClientError> {
    let key =
        ExpectedProvingKey::transfer_ring_authority(inputs.inputs.len(), inputs.outputs.len())?;
    transfer_request(TransferKind::RingAuthority, inputs, key)
}

pub(crate) fn merge(inputs: &MergeInputs) -> Result<CircuitRequest<'_>, ClientError> {
    let key = ExpectedProvingKey::merge(inputs.inputs.len())?;
    Ok(in_response(
        Source::Merge(MergeKind::Confidential, Cow::Borrowed(inputs)),
        key,
    ))
}

pub(crate) fn merge_ring(inputs: &MergeInputs) -> Result<CircuitRequest<'_>, ClientError> {
    let key = ExpectedProvingKey::merge_ring(inputs.inputs.len())?;
    Ok(in_response(
        Source::Merge(MergeKind::Ring, Cow::Borrowed(inputs)),
        key,
    ))
}

/// A batch proof runs far longer than a connection should be held open, so it
/// always queues.
pub(crate) fn batch_address_append(
    inputs: &BatchAddressAppendInputs,
) -> Result<CircuitRequest<'static>, ClientError> {
    Ok(CircuitRequest {
        source: Source::Wire(Zeroizing::new(to_json_batch_address_append(inputs))),
        proving_key: ExpectedProvingKey::batch_address_append(
            inputs.tree_height,
            inputs.batch_size,
        )?,
        delivery: Delivery::Queued,
    })
}
