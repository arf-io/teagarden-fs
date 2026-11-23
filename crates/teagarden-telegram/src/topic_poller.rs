use std::time::Duration;

use crate::{
    client::BlockTransport,
    error::{Result, TelegramError},
    types::DocumentInfo,
};

/// One fully enumerated topic batch with a stable upper bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicPollBatch {
    /// Highest raw message ID observed when this batch began.
    pub high_water_id: i64,
    /// All raw IDs in the batch, ascending so callers can apply them in order.
    pub raw_message_ids: Vec<i64>,
    /// Documents in the batch, ascending by message ID.
    pub documents: Vec<DocumentInfo>,
}

/// Enumerate all raw messages newer than `after_message_id` through one fixed
/// high-water mark. The API pages newest-first; this returns oldest-first.
pub async fn collect_topic_batch(
    transport: &dyn BlockTransport,
    group_id: i64,
    topic_id: i64,
    after_message_id: i64,
    page_size: usize,
) -> Result<TopicPollBatch> {
    let limit = page_size.clamp(1, 100);
    let first = transport
        .list_topic_page(
            group_id,
            topic_id,
            Some(after_message_id),
            None,
            None,
            limit,
        )
        .await?;
    let Some(high_water_id) = first.raw_message_ids.first().copied() else {
        return Ok(TopicPollBatch {
            high_water_id: after_message_id,
            raw_message_ids: Vec::new(),
            documents: Vec::new(),
        });
    };
    if high_water_id <= after_message_id {
        return Ok(TopicPollBatch {
            high_water_id: after_message_id,
            raw_message_ids: Vec::new(),
            documents: Vec::new(),
        });
    }
    let exclusive_max = high_water_id
        .checked_add(1)
        .ok_or_else(|| TelegramError::Api("topic message ID overflow".into()))?;
    let mut offset = None;
    let mut raw_desc = Vec::new();
    let mut documents_desc = Vec::new();
    loop {
        let page = if offset.is_none() {
            first.clone()
        } else {
            transport
                .list_topic_page(
                    group_id,
                    topic_id,
                    Some(after_message_id),
                    Some(exclusive_max),
                    offset,
                    limit,
                )
                .await?
        };
        if page.raw_message_ids.is_empty() && !page.exhausted {
            return Err(TelegramError::Api(
                "topic pagination returned an empty nonterminal page".into(),
            ));
        }
        offset = page.raw_message_ids.last().copied();
        raw_desc.extend(page.raw_message_ids);
        documents_desc.extend(page.documents);
        if page.exhausted {
            break;
        }
        if offset.is_none() {
            return Err(TelegramError::Api(
                "topic pagination did not advance its raw-message cursor".into(),
            ));
        }
    }
    raw_desc.sort_unstable();
    documents_desc.sort_by_key(|document| document.message_id);
    Ok(TopicPollBatch {
        high_water_id,
        raw_message_ids: raw_desc,
        documents: documents_desc,
    })
}

/// Poll cadence: four seconds after recent filesystem activity and thirty
/// seconds while idle.
pub fn poll_interval(active: bool) -> Duration {
    Duration::from_secs(if active { 4 } else { 30 })
}
