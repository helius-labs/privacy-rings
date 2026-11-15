use s3::request::tokio_backend::ReqwestRequest as RequestImpl;
use s3::{
    command::{Command, Multipart},
    error::S3Error,
    request::{Request, ResponseData},
    serde_types::Part,
    utils::PutStreamResponse,
    Bucket,
};
use tokio::io::{AsyncRead, AsyncReadExt};

// 100 MiB per part. S3/R2 allows max 10,000 parts, so this supports up to ~977 GB files.
// The previous 8 MiB default (from rust-s3) only supported ~78 GB, which was exceeded by
// merged snapshots causing "Part number must be an integer between 1 and 10000" errors.
const MULTIPART_CHUNK_SIZE: usize = 100 * 1024 * 1024;
const MULTIPART_CHUNK_SIZE_U64: u64 = MULTIPART_CHUNK_SIZE as u64;

async fn read_chunk<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, S3Error> {
    let mut chunk = Vec::with_capacity(MULTIPART_CHUNK_SIZE);
    let mut take = reader.take(MULTIPART_CHUNK_SIZE_U64);
    take.read_to_end(&mut chunk).await?;
    Ok(chunk)
}

// Uploads a stream with one part buffered at a time.
pub async fn put_object_stream_custom<R: AsyncRead + Unpin>(
    bucket: &Bucket,
    reader: &mut R,
    s3_path: impl AsRef<str>,
) -> Result<PutStreamResponse, S3Error> {
    put_object_stream_with_content_type_and_retries(
        bucket,
        reader,
        s3_path.as_ref(),
        "application/octet-stream",
    )
    .await
}

async fn put_object_stream_with_content_type_and_retries<R: AsyncRead + Unpin>(
    bucket: &Bucket,
    reader: &mut R,
    s3_path: &str,
    content_type: &str,
) -> Result<PutStreamResponse, S3Error> {
    let first_chunk = read_chunk(reader).await?;
    if first_chunk.len() < MULTIPART_CHUNK_SIZE {
        let total_size = first_chunk.len();
        let response = bucket
            .put_object_with_content_type(s3_path, &first_chunk, content_type)
            .await?;
        if !(200..300).contains(&response.status_code()) {
            return Err(error_from_response_data(response)?);
        }
        return Ok(PutStreamResponse::new(response.status_code(), total_size));
    }

    let upload = bucket
        .initiate_multipart_upload(s3_path, content_type)
        .await?;
    let result = async {
        let mut chunk = first_chunk;
        let mut total_size = 0;
        let mut parts = Vec::new();
        loop {
            total_size += chunk.len();
            let part_number = u32::try_from(parts.len() + 1).unwrap_or(u32::MAX);
            let response = make_multipart_request(
                bucket,
                &upload.key,
                chunk,
                part_number,
                &upload.upload_id,
                content_type,
            )
            .await?;
            if !(200..300).contains(&response.status_code()) {
                return Err(error_from_response_data(response)?);
            }
            parts.push(Part {
                etag: response.as_str()?.to_string(),
                part_number,
            });
            // Finish the upload before reading another part, including the HTTP client's body copies.
            chunk = read_chunk(reader).await?;
            if chunk.is_empty() {
                break;
            }
        }
        let response = bucket
            .complete_multipart_upload(&upload.key, &upload.upload_id, parts)
            .await?;
        if !(200..300).contains(&response.status_code()) {
            return Err(error_from_response_data(response)?);
        }
        Ok(PutStreamResponse::new(response.status_code(), total_size))
    }
    .await;
    if result.is_err() {
        let _ = bucket.abort_upload(&upload.key, &upload.upload_id).await;
    }
    result
}

async fn make_multipart_request(
    bucket: &Bucket,
    path: &str,
    chunk: Vec<u8>,
    part_number: u32,
    upload_id: &str,
    content_type: &str,
) -> Result<ResponseData, S3Error> {
    let command = Command::PutObject {
        content: &chunk,
        multipart: Some(Multipart::new(part_number, upload_id)), // upload_id: &msg.upload_id,
        content_type,
        custom_headers: None,
    };
    let request = RequestImpl::new(bucket, path, command).await?;
    request.response_data(true).await
}

fn error_from_response_data(response_data: ResponseData) -> Result<S3Error, S3Error> {
    let utf8_content = String::from_utf8(response_data.as_slice().to_vec())?;
    Err(S3Error::HttpFailWithBody(
        response_data.status_code(),
        utf8_content,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3::{creds::Credentials, Region};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
        thread::JoinHandle,
        time::{Duration, Instant},
    };
    use tokio::io::ReadBuf;

    struct BudgetedReader {
        remaining: usize,
        read: usize,
        acknowledged: Arc<AtomicUsize>,
        peak: usize,
        fail_after: Option<usize>,
    }

    impl AsyncRead for BudgetedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.remaining == 0 || buffer.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.fail_after.is_some_and(|limit| self.read >= limit) {
                return Poll::Ready(Err(std::io::Error::other("source failed")));
            }
            let pending = self.read - self.acknowledged.load(Ordering::SeqCst);
            if pending >= MULTIPART_CHUNK_SIZE {
                return Poll::Ready(Err(std::io::Error::other(
                    "read ahead of the unacknowledged part",
                )));
            }
            let mut count = self
                .remaining
                .min(buffer.remaining())
                .min(64 * 1024)
                .min(MULTIPART_CHUNK_SIZE - pending);
            if let Some(limit) = self.fail_after {
                count = count.min(limit - self.read);
            }
            buffer.initialize_unfilled_to(count).fill(0x5a);
            buffer.advance(count);
            self.remaining -= count;
            self.read += count;
            self.peak = self.peak.max(pending + count);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct Uploads {
        parts: Vec<usize>,
        completed: bool,
        aborted: bool,
    }

    fn server(size: usize, fail_completion: bool) -> (Bucket, BudgetedReader, JoinHandle<Uploads>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let acknowledged = Arc::new(AtomicUsize::new(0));
        let uploaded = acknowledged.clone();
        let handle = std::thread::spawn(move || {
            let mut uploads = Uploads::default();
            loop {
                let deadline = Instant::now() + Duration::from_secs(30);
                let (mut socket, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "expected another S3 request");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut first_line = String::new();
                reader.read_line(&mut first_line).unwrap();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let put = first_line.starts_with("PUT ");
                let mut body = Vec::new();
                let mut left = length;
                let mut buffer = [0; 64 * 1024];
                while left > 0 {
                    let count = reader.read(&mut buffer[..left.min(64 * 1024)]).unwrap();
                    assert!(count > 0);
                    if put {
                        assert!(buffer[..count].iter().all(|byte| *byte == 0x5a));
                    } else {
                        body.extend_from_slice(&buffer[..count]);
                    }
                    left -= count;
                }
                let (status, answer, done) = if put {
                    if let Some(query) = first_line.split("partNumber=").nth(1) {
                        let part = query
                            .split(['&', ' '])
                            .next()
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        assert_eq!(part, uploads.parts.len() + 1);
                    }
                    uploads.parts.push(length);
                    uploaded.fetch_add(length, Ordering::SeqCst);
                    (200, String::new(), !first_line.contains("uploadId="))
                } else if first_line.starts_with("DELETE ") {
                    uploads.aborted = true;
                    (204, String::new(), true)
                } else if first_line.contains("uploadId=") {
                    if fail_completion {
                        (400, "<Error><Code>InvalidPart</Code><Message>completion failed</Message></Error>".into(), false)
                    } else {
                        let body = String::from_utf8(body).unwrap();
                        for part in 1..=uploads.parts.len() {
                            assert!(body.contains(&format!("<PartNumber>{part}</PartNumber>")));
                        }
                        uploads.completed = true;
                        (200, String::new(), true)
                    }
                } else {
                    (200, "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>snapshot</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>".into(), false)
                };
                write!(socket, "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nETag: \"part\"\r\nConnection: close\r\n\r\n{answer}", answer.len()).unwrap();
                if done {
                    return uploads;
                }
            }
        });
        let bucket = *Bucket::new(
            "bucket",
            Region::Custom {
                region: "us-east-1".into(),
                endpoint,
            },
            Credentials::new(Some("test"), Some("test"), None, None, None).unwrap(),
        )
        .unwrap()
        .with_path_style();
        (
            bucket,
            BudgetedReader {
                remaining: size,
                read: 0,
                acknowledged,
                peak: 0,
                fail_after: None,
            },
            handle,
        )
    }

    #[tokio::test]
    async fn large_upload_never_reads_ahead_of_the_current_part() {
        let size = 13 * MULTIPART_CHUNK_SIZE + 17;
        let (bucket, mut reader, server) = server(size, false);
        let result = put_object_stream_custom(&bucket, &mut reader, "snapshot")
            .await
            .unwrap();
        let uploads = server.join().unwrap();
        assert_eq!(result.uploaded_bytes(), size);
        assert_eq!(uploads.parts.len(), 14);
        assert_eq!(uploads.parts.iter().sum::<usize>(), size);
        assert_eq!(uploads.parts.last(), Some(&17));
        assert!(uploads.completed);
        assert!(!uploads.aborted);
        assert!(reader.peak <= MULTIPART_CHUNK_SIZE);
    }

    #[tokio::test]
    async fn exact_part_boundary_does_not_upload_an_empty_part() {
        let (bucket, mut reader, server) = server(MULTIPART_CHUNK_SIZE, false);
        put_object_stream_custom(&bucket, &mut reader, "snapshot")
            .await
            .unwrap();
        let uploads = server.join().unwrap();
        assert_eq!(uploads.parts, vec![MULTIPART_CHUNK_SIZE]);
        assert!(uploads.completed);
    }

    #[tokio::test]
    async fn read_failure_aborts_the_incomplete_upload() {
        let (bucket, mut reader, server) = server(2 * MULTIPART_CHUNK_SIZE, false);
        reader.fail_after = Some(MULTIPART_CHUNK_SIZE + 17);
        assert!(put_object_stream_custom(&bucket, &mut reader, "snapshot")
            .await
            .is_err());
        let uploads = server.join().unwrap();
        assert!(uploads.aborted);
        assert!(!uploads.completed);
        assert_eq!(uploads.parts, vec![MULTIPART_CHUNK_SIZE]);
    }

    #[tokio::test]
    async fn rejected_completion_is_not_reported_as_success() {
        let (bucket, mut reader, server) = server(MULTIPART_CHUNK_SIZE, true);
        assert!(put_object_stream_custom(&bucket, &mut reader, "snapshot")
            .await
            .is_err());
        let uploads = server.join().unwrap();
        assert!(uploads.aborted);
        assert!(!uploads.completed);
    }
}
