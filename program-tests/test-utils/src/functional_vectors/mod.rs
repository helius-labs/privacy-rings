//! Functional transact vectors: one ring-agnostic catalog of successful
//! scenarios, exported to `test-vectors/transact_functional.json`.
//!
//! The default-ring runner in `shielded-pool-tests` and the custom-ring runner
//! in the custom-rings repository both execute this catalog, so a scenario that
//! settles in one ring and not the other shows up as a compatibility gap.

mod catalog;
pub mod coverage;
pub mod spec;
mod types;

use anyhow::Result;
pub use catalog::catalog;
pub use types::*;

const COMMITTED: &str = include_str!("../../../../test-vectors/transact_functional.json");
const COMMITTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/transact_functional.json"
);

const DESCRIPTION: &str = "Successful transact scenarios every ring must settle, in ring-agnostic terms: actors, funded notes, ordered steps of input slots, output slots and public legs, and the expected state after each step. rings states per ring whether the case runs, is not applicable by design, or is pending with a reason. Slots past the listed ones are padding the runner chooses for its shape. Produced by program-tests/test-utils/src/functional_vectors: cargo test -p spr-test-utils --test functional_vectors write_functional_vectors -- --ignored";

/// The catalog as the generator computes it.
pub fn compute_file() -> Result<FunctionalVectorFile> {
    let vectors = catalog()?;
    Ok(FunctionalVectorFile {
        description: DESCRIPTION.to_string(),
        coverage: coverage::coverage(&vectors),
        vectors,
    })
}

/// The committed `test-vectors/transact_functional.json`.
pub fn committed_file() -> Result<FunctionalVectorFile> {
    Ok(serde_json::from_str(COMMITTED)?)
}

/// Rewrites `test-vectors/transact_functional.json`: pretty JSON, one trailing newline.
pub fn write_committed_file(file: &FunctionalVectorFile) -> Result<()> {
    let mut json = serde_json::to_string_pretty(file)?;
    json.push('\n');
    std::fs::write(COMMITTED_PATH, json)?;
    Ok(())
}

/// The committed vector named `name`.
pub fn committed_vector(name: &str) -> Result<FunctionalVector> {
    committed_file()?
        .vectors
        .into_iter()
        .find(|vector| vector.name == name)
        .ok_or_else(|| anyhow::anyhow!("no functional vector named {name}"))
}
