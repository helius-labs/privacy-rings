use super::{NitroCheckpoint, NitroPolicyError, NitroPolicyUpdate, NitroTrust};

/// Durable compare-and-set scoped to the pinned network and security domain.
/// Check the update against storage inside the transaction before committing it.
pub trait NitroCheckpointStore: Send + Sync {
    fn current(&self, trust: &NitroTrust) -> Result<Option<NitroCheckpoint>, NitroPolicyError>;
    fn accept(
        &self,
        trust: &NitroTrust,
        update: &NitroPolicyUpdate<'_>,
    ) -> Result<bool, NitroPolicyError>;
}

#[cfg(unix)]
pub use unix::UnixNitroCheckpointStore;

#[cfg(unix)]
mod unix {
    use std::{
        fs::{File, OpenOptions},
        io::{ErrorKind, Read},
        os::unix::fs::OpenOptionsExt,
        path::{Path, PathBuf},
    };

    use super::{
        NitroCheckpoint, NitroCheckpointStore, NitroPolicyError, NitroPolicyUpdate, NitroTrust,
    };

    const MAX_CHECKPOINT_BYTES: u64 = 1024;

    /// File-backed storage for an application-owned directory on a local Unix filesystem.
    /// The lock file stays in place across atomic replacements.
    pub struct UnixNitroCheckpointStore {
        directory: PathBuf,
    }

    impl UnixNitroCheckpointStore {
        pub fn open(directory: &Path) -> Result<Self, NitroPolicyError> {
            let directory = directory
                .canonicalize()
                .map_err(|_| NitroPolicyError::Storage)?;
            if !directory.is_dir() {
                return Err(NitroPolicyError::Storage);
            }
            Ok(Self { directory })
        }

        fn with_lock<T>(
            &self,
            trust: &NitroTrust,
            run: impl FnOnce(&Path) -> Result<T, NitroPolicyError>,
        ) -> Result<T, NitroPolicyError> {
            let name = format!(
                "{}-{}",
                trust.network().as_str(),
                hex::encode(trust.security_domain_id())
            );
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(self.directory.join(format!("{name}.lock")))
                .map_err(|_| NitroPolicyError::Storage)?;
            lock.lock().map_err(|_| NitroPolicyError::Storage)?;
            run(&self.directory.join(format!("{name}.json")))
        }

        fn read(path: &Path) -> Result<Option<NitroCheckpoint>, NitroPolicyError> {
            let file = match File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(NitroPolicyError::Storage),
            };
            let mut bytes = Vec::new();
            file.take(MAX_CHECKPOINT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| NitroPolicyError::Storage)?;
            if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
                return Err(NitroPolicyError::Storage);
            }
            let checkpoint: NitroCheckpoint =
                serde_json::from_slice(&bytes).map_err(|_| NitroPolicyError::Storage)?;
            if !valid(&checkpoint) {
                return Err(NitroPolicyError::Storage);
            }
            Ok(Some(checkpoint))
        }
    }

    impl NitroCheckpointStore for UnixNitroCheckpointStore {
        fn current(&self, trust: &NitroTrust) -> Result<Option<NitroCheckpoint>, NitroPolicyError> {
            self.with_lock(trust, Self::read)
        }

        fn accept(
            &self,
            trust: &NitroTrust,
            update: &NitroPolicyUpdate<'_>,
        ) -> Result<bool, NitroPolicyError> {
            let candidate = update.checkpoint();
            if !valid(candidate) {
                return Err(NitroPolicyError::Storage);
            }
            self.with_lock(trust, |path| {
                let prior = Self::read(path)?;
                if !update.advances(prior.as_ref()) {
                    return Ok(false);
                }
                if prior.as_ref() == Some(candidate) {
                    // A previous rename can be visible even if syncing failed.
                    self.sync_directory()?;
                    return Ok(true);
                }
                let mut next = tempfile::NamedTempFile::new_in(&self.directory)
                    .map_err(|_| NitroPolicyError::Storage)?;
                serde_json::to_writer(next.as_file_mut(), candidate)
                    .map_err(|_| NitroPolicyError::Storage)?;
                next.as_file()
                    .sync_all()
                    .map_err(|_| NitroPolicyError::Storage)?;
                next.persist(path).map_err(|_| NitroPolicyError::Storage)?;
                self.sync_directory()?;
                Ok(true)
            })
        }
    }

    impl UnixNitroCheckpointStore {
        fn sync_directory(&self) -> Result<(), NitroPolicyError> {
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| NitroPolicyError::Storage)
        }
    }
    fn valid(checkpoint: &NitroCheckpoint) -> bool {
        checkpoint.sequence > 0
            && checkpoint.minimum_custody_epoch > 0
            && checkpoint.digest != [0; 32]
    }
}
