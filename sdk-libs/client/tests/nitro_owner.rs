use std::{cell::Cell, future::ready, pin::pin, sync::mpsc};

use super::*;

#[test]
fn timed_out_signer_holds_its_slot_without_blocking_runtime_shutdown() {
    let worker = Arc::new(Semaphore::new(1));
    let budget = Duration::from_secs(1);
    let (stopped, shutdown) = mpsc::channel();
    let (finish, wait) = mpsc::channel();
    let runtime_thread = std::thread::spawn({
        let worker = worker.clone();
        move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            runtime.block_on(async {
                let (started, entered) = mpsc::channel();
                let mut running = pin!(owner_call(&worker, budget, ready(Ok(())), move || {
                    started.send(()).unwrap();
                    wait.recv().unwrap();
                    Ok(())
                }));
                assert!(futures::poll!(&mut running).is_pending());
                entered.recv_timeout(Duration::from_secs(5)).unwrap();
                tokio::time::advance(budget).await;
                assert!(matches!(
                    running.await,
                    Err(NitroDecryptionError::OwnerTimeout)
                ));

                let mut blocked = pin!(owner_call::<()>(&worker, budget, ready(Ok(())), || {
                    panic!("a stalled signer still owns the permit")
                }));
                assert!(futures::poll!(&mut blocked).is_pending());
                tokio::time::advance(budget).await;
                assert!(matches!(
                    blocked.await,
                    Err(NitroDecryptionError::OwnerTimeout)
                ));
            });
            drop(runtime);
            stopped.send(()).unwrap();
        }
    });
    let shutdown = shutdown.recv_timeout(Duration::from_secs(5));
    finish.send(()).unwrap();
    runtime_thread.join().unwrap();
    shutdown.expect("the runtime should exit before the signer returns");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    assert_eq!(
        runtime
            .block_on(owner_call(
                &worker,
                Duration::from_secs(5),
                ready(Ok(())),
                || Ok(42)
            ))
            .unwrap(),
        42
    );
}

#[tokio::test]
async fn queued_signer_checks_policy_after_acquiring_its_slot() {
    let worker = Arc::new(Semaphore::new(1));
    let previous = worker.acquire().await.unwrap();
    let revoked = Cell::new(false);
    let mut approval = pin!(owner_call::<()>(
        &worker,
        Duration::from_secs(5),
        async {
            if revoked.get() {
                return Err(NitroPolicyError::Superseded.into());
            }
            Ok(())
        },
        || panic!("the queued approval must never reach the signer"),
    ));
    assert!(futures::poll!(&mut approval).is_pending());
    revoked.set(true);
    drop(previous);
    assert!(matches!(
        approval.await,
        Err(NitroDecryptionError::Policy(NitroPolicyError::Superseded))
    ));
    assert_eq!(worker.available_permits(), 1);
}
