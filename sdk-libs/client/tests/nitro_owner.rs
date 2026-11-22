use std::{pin::pin, sync::mpsc};

use super::*;

#[tokio::test(start_paused = true)]
async fn timed_out_wallet_signer_holds_its_permit_until_it_finishes() {
    let worker = Arc::new(Semaphore::new(1));
    let budget = Duration::from_secs(1);
    let (started, entered) = oneshot::channel();
    let (finish, wait) = mpsc::channel();
    let running = tokio::spawn({
        let worker = worker.clone();
        async move {
            owner_call(&worker, budget, move || {
                started.send(()).unwrap();
                wait.recv().unwrap();
                Ok(())
            })
            .await
        }
    });
    entered.await.unwrap();
    tokio::time::advance(budget).await;
    assert!(matches!(
        running.await.unwrap(),
        Err(NitroDecryptionError::OwnerTimeout)
    ));

    let mut blocked = pin!(owner_call::<()>(&worker, budget, || {
        panic!("a stalled signer still owns the permit")
    }));
    assert!(futures::poll!(&mut blocked).is_pending());
    tokio::time::advance(budget).await;
    assert!(matches!(
        blocked.await,
        Err(NitroDecryptionError::OwnerTimeout)
    ));
    finish.send(()).unwrap();
    assert_eq!(owner_call(&worker, budget, || Ok(42)).await.unwrap(), 42);
}
