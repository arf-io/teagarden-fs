use std::time::Duration;
use teagarden_telegram::client::BlockTransport;
use teagarden_telegram::mock::MockTransport;
use teagarden_telegram::topic_poller::{collect_topic_batch, poll_interval};

#[tokio::test]
async fn topic_poller_captures_fixed_high_water_and_applies_raw_pages_ascending() {
    let transport = MockTransport::new();
    for id in 1..=251 {
        if id % 7 == 0 {
            transport.put_document(id, -100, 42, "object.tgf", vec![id as u8]);
        } else {
            transport.put_text_message(id, -100, 42);
        }
    }
    let batch = collect_topic_batch(&transport, -100, 42, 100, 100)
        .await
        .unwrap();
    assert_eq!(batch.high_water_id, 251);
    assert_eq!(batch.raw_message_ids.len(), 151);
    assert_eq!(batch.raw_message_ids.first(), Some(&101));
    assert_eq!(batch.raw_message_ids.last(), Some(&251));
    assert_eq!(batch.documents.first().unwrap().message_id, 105);
    assert_eq!(batch.documents.last().unwrap().message_id, 245);
}

#[test]
fn topic_polling_uses_short_active_and_long_idle_intervals() {
    assert_eq!(poll_interval(true), Duration::from_secs(4));
    assert_eq!(poll_interval(false), Duration::from_secs(30));
}

#[tokio::test]
async fn document_enumeration_is_newest_first_paginated_and_scoped_to_group_and_topic() {
    let transport = MockTransport::new();
    transport.put_document(1, -100, 42, "teagarden-header-v1.tgh", b"one".to_vec());
    transport.put_document(2, -100, 42, "teagarden-header-v1.tgh", b"two".to_vec());
    transport.put_document(
        3,
        -100,
        43,
        "teagarden-header-v1.tgh",
        b"wrong-topic".to_vec(),
    );
    transport.put_document(
        4,
        -101,
        42,
        "teagarden-header-v1.tgh",
        b"wrong-group".to_vec(),
    );

    let first = transport
        .list_topic_documents(-100, 42, None, 1)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].message_id, 2);
    assert_eq!(first[0].filename, "teagarden-header-v1.tgh");

    let second = transport
        .list_topic_documents(-100, 42, Some(2), 100)
        .await
        .unwrap();
    assert_eq!(
        second.iter().map(|d| d.message_id).collect::<Vec<_>>(),
        vec![1]
    );
}

#[tokio::test]
async fn document_upload_failure_is_not_reported_as_success() {
    let transport = MockTransport::new();
    transport.set_fail_uploads_after(0);
    let err = transport
        .upload_block(b"TGHD header", "teagarden-header-v1.tgh")
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn topic_pages_include_raw_message_ids_and_honor_bounded_pagination() {
    let transport = MockTransport::new();
    // Text messages occupy ids between object documents. The caller must advance
    // by raw topic messages so a page containing no documents cannot stall.
    transport.put_document(10, -100, 42, "object.tgf", b"ten".to_vec());
    transport.put_text_message(9, -100, 42);
    transport.put_document(8, -100, 42, "object.tgf", b"eight".to_vec());
    transport.put_text_message(7, -100, 42);
    transport.put_document(6, -100, 42, "object.tgf", b"six".to_vec());
    transport.put_text_message(5, -100, 42);
    transport.put_document(4, -100, 42, "object.tgf", b"four".to_vec());
    transport.put_document(3, -100, 42, "wrong-topic.tgf", b"other".to_vec());

    let first = transport
        .list_topic_page(-100, 42, Some(3), Some(11), None, 3)
        .await
        .unwrap();
    assert_eq!(first.raw_message_ids, vec![10, 9, 8]);
    assert_eq!(
        first
            .documents
            .iter()
            .map(|d| d.message_id)
            .collect::<Vec<_>>(),
        vec![10, 8]
    );
    assert!(!first.exhausted);

    let second = transport
        .list_topic_page(-100, 42, Some(3), Some(11), Some(8), 3)
        .await
        .unwrap();
    assert_eq!(second.raw_message_ids, vec![7, 6, 5]);
    assert_eq!(
        second
            .documents
            .iter()
            .map(|d| d.message_id)
            .collect::<Vec<_>>(),
        vec![6]
    );
    assert!(!second.exhausted);

    let last = transport
        .list_topic_page(-100, 42, Some(3), Some(11), Some(5), 3)
        .await
        .unwrap();
    assert_eq!(last.raw_message_ids, vec![4]);
    assert_eq!(
        last.documents
            .iter()
            .map(|d| d.message_id)
            .collect::<Vec<_>>(),
        vec![4]
    );
    assert!(last.exhausted);
}

#[tokio::test]
async fn topic_page_backfill_crosses_the_hundred_message_boundary() {
    let transport = MockTransport::new();
    for id in 1..=251 {
        if id % 10 == 0 {
            transport.put_document(id, -100, 42, "object.tgf", vec![id as u8]);
        } else {
            transport.put_text_message(id, -100, 42);
        }
    }

    let mut cursor = None;
    let mut seen = Vec::new();
    let mut page_sizes = Vec::new();
    loop {
        let page = transport
            .list_topic_page(-100, 42, Some(0), Some(252), cursor, 100)
            .await
            .unwrap();
        page_sizes.push(page.raw_message_ids.len());
        cursor = page.raw_message_ids.last().copied();
        seen.extend(page.raw_message_ids);
        if page.exhausted {
            break;
        }
    }

    assert_eq!(page_sizes, vec![100, 100, 51]);
    assert_eq!(seen.len(), 251);
    assert_eq!(seen.first(), Some(&251));
    assert_eq!(seen.last(), Some(&1));
}

#[tokio::test]
async fn stored_document_with_lost_upload_ack_is_still_an_error() {
    let transport = MockTransport::new();
    transport.withhold_upload_acks(1);
    let err = transport
        .upload_block(b"TGHD header", "teagarden-header-v1.tgh")
        .await;
    assert!(err.is_err());
    assert_eq!(transport.message_count(), 1);
}
