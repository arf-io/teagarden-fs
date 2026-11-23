//! Bot-HTTP-API transport for parallel block uploads.
//!
//! A storage bot uploads blocks via the Telegram **Bot HTTP API**
//! (`api.telegram.org/bot<token>/sendDocument`) rather than MTProto. The Bot HTTP
//! API does not need an MTProto access hash: it resolves the chat server-side
//! from a numeric `chat_id`, so a bot that is a group member just needs
//! the group id and the topic's `message_thread_id` to post a block — no per-session
//! access_hash, no resolution that can hang.
//!
//! Credit: this Bot-API-for-parallel-uploads approach was demonstrated by the
//! **TGstorage** project (DraxonV1, <https://github.com/DraxonV1/TGstorage>), which
//! is where the idea of uploading through the Bot HTTP API, which needs no access
//! hash, came from.
//!
//! Downloads still go by `message_id`, which the Bot API cannot fetch arbitrarily;
//! those are served by the user's MTProto session via [`MultiTransport`](crate::multi::MultiTransport)
//! fallthrough. So a `BotApiTransport` parallelizes the (bottleneck) UPLOAD path and
//! deliberately fails reads/deletes so the pool routes them to the MTProto session.

use async_trait::async_trait;

use crate::client::BlockTransport;
use crate::error::{Result, TelegramError};
use crate::types::{DocumentInfo, DownloadResult, UploadResult};

/// A single storage bot that uploads blocks via the Telegram Bot HTTP API.
pub struct BotApiTransport {
    client: reqwest::Client,
    token: String,
    /// Bot API base URL. Always `https://api.telegram.org` in production; a
    /// crate-private test seam points it elsewhere (see `with_api_base`).
    api_base: String,
    /// Numeric chat id of the shared supergroup, in Bot-API form (`-100<id>`).
    chat_id: i64,
    /// Forum topic id (`message_thread_id`) this volume's blocks post into.
    topic_id: i64,
}

impl BotApiTransport {
    /// Build a bot-API transport for `token`, targeting `group_id`'s `topic_id`.
    ///
    /// `group_id` is the raw supergroup id (as stored in the volume config); it is
    /// converted to the Bot-API `-100`-prefixed form internally.
    pub fn new(token: impl Into<String>, group_id: i64, topic_id: i64) -> Self {
        Self::with_api_base(token, group_id, topic_id, "https://api.telegram.org")
    }

    /// As [`Self::new`], against a different Bot API base URL. Crate-private: it
    /// exists so tests can aim the real HTTP path at an address that fails.
    pub(crate) fn with_api_base(
        token: impl Into<String>,
        group_id: i64,
        topic_id: i64,
        api_base: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("build reqwest client (TLS/resolver init)");
        Self {
            client,
            token: token.into(),
            api_base: api_base.into(),
            chat_id: to_bot_api_chat_id(group_id),
            topic_id,
        }
    }

    /// Render a reqwest error WITHOUT the bot token (telegram-H3).
    ///
    /// reqwest's `Display` appends "for url (...)", and the Bot API carries the
    /// token in the URL path, so a plain `{e}` wrote the token into every error
    /// — and from there into `MultiTransport`'s warnings and the FUSE upload
    /// worker's log. `without_url()` drops the URL; replacing any remaining
    /// occurrence of the token (e.g. inside a source error) is a backstop.
    fn redact(&self, e: reqwest::Error) -> String {
        redact(&self.token, e)
    }

    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.api_base, self.token, method)
    }
}

/// Render a reqwest error WITHOUT the bot token. reqwest's `Display` appends
/// "for url (...)", and the Bot API carries the token in the URL path.
/// `without_url()` drops the URL; replacing any remaining occurrence of the token
/// (e.g. inside a source error) is a backstop.
fn redact(token: &str, e: reqwest::Error) -> String {
    let text = e.without_url().to_string();
    if token.is_empty() {
        text
    } else {
        text.replace(token, "<redacted>")
    }
}

/// A bot's identity, as the Bot API `getMe` reports it. Contains no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotIdentity {
    /// Numeric bot user id (also the part of its token before `:`).
    pub id: i64,
    /// The bot's `@username`, without the `@`.
    pub username: String,
}

const BOT_API: &str = "https://api.telegram.org";

fn short_lived_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| TelegramError::Api(format!("build HTTP client: {}", e.without_url())))
}

/// Read a Bot API JSON reply. A reply with `ok != true` becomes an error that
/// carries Telegram's `description` (never the token).
async fn bot_api_result(
    token: &str,
    method: &str,
    resp: reqwest::Response,
) -> Result<serde_json::Value> {
    let status = resp.status();
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| TelegramError::Api(format!("Bot API {method} reply: {}", redact(token, e))))?;
    if json.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok(json
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null));
    }
    let description = json
        .get("description")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("no description")
        .replace(token, "<redacted>");
    Err(TelegramError::Api(format!(
        "the Bot API refused {method} (HTTP {}): {description}",
        status.as_u16()
    )))
}

/// Validate a bot token with the Bot API `getMe` method and return the bot's
/// identity. Fails if the token is rejected, the account is not a bot, or the
/// bot has no username (the user session needs it to promote the bot). No
/// error ever contains the token.
pub async fn get_me(token: &str) -> Result<BotIdentity> {
    get_me_at(BOT_API, token).await
}

pub(crate) async fn get_me_at(api_base: &str, token: &str) -> Result<BotIdentity> {
    let resp = short_lived_client()?
        .get(format!("{api_base}/bot{token}/getMe"))
        .send()
        .await
        .map_err(|e| TelegramError::Api(format!("Bot API getMe: {}", redact(token, e))))?;
    let result = bot_api_result(token, "getMe", resp).await?;
    if result.get("is_bot").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(TelegramError::Api(
            "getMe says this token does not belong to a bot account".into(),
        ));
    }
    let id = result
        .get("id")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| TelegramError::Api("getMe reply has no bot id".into()))?;
    let username = result
        .get("username")
        .and_then(serde_json::Value::as_str)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| TelegramError::Api("getMe reply has no bot username".into()))?
        .to_string();
    Ok(BotIdentity { id, username })
}

/// Make the bot leave the shared storage group (Bot API `leaveChat`), using the
/// bot's own token. `group_id` is the raw supergroup id from the volume config.
pub async fn leave_chat(token: &str, group_id: i64) -> Result<()> {
    leave_chat_at(BOT_API, token, group_id).await
}

pub(crate) async fn leave_chat_at(api_base: &str, token: &str, group_id: i64) -> Result<()> {
    let resp = short_lived_client()?
        .post(format!("{api_base}/bot{token}/leaveChat"))
        .form(&[("chat_id", to_bot_api_chat_id(group_id).to_string())])
        .send()
        .await
        .map_err(|e| TelegramError::Api(format!("Bot API leaveChat: {}", redact(token, e))))?;
    bot_api_result(token, "leaveChat", resp).await.map(drop)
}

/// Convert a raw supergroup id to the Bot-API `-100`-prefixed chat id.
/// (A supergroup with raw id `4320408240` is `-1004320408240` to the Bot API.)
fn to_bot_api_chat_id(group_id: i64) -> i64 {
    if group_id < 0 {
        group_id // already in -100... form
    } else {
        -(1_000_000_000_000_i64 + group_id)
    }
}

#[async_trait]
impl BlockTransport for BotApiTransport {
    async fn upload_block(&self, data: &[u8], filename: &str) -> Result<UploadResult> {
        let size = data.len();
        // No Content-Type on the document part, deliberately.
        //
        // The MTProto path (`client.rs`) sends an empty `mime_type` because a
        // constant non-empty MIME on every upload is itself a fingerprint —
        // "application/octet-stream" on every document says "this account
        // uploads anonymous binary blobs" as loudly as any magic byte would.
        // This path used to send exactly that constant, which both contradicted
        // the MTProto rationale and made the documented "every document is sent
        // with an empty MIME type" (docs/FORMAT.md §3) false for Bot API uploads.
        //
        // reqwest omits the part's Content-Type header entirely when no mime is
        // set (`PartMetadata::mime` is `None`), which is the closest this
        // transport can get to the MTProto behaviour: HTTP has no way to send a
        // literally empty Content-Type, so the header is absent rather than
        // constant.
        let part = reqwest::multipart::Part::bytes(data.to_vec()).file_name(filename.to_string());
        let form = reqwest::multipart::Form::new()
            .text("chat_id", self.chat_id.to_string())
            .text("message_thread_id", self.topic_id.to_string())
            .part("document", part);

        let resp = self
            .client
            .post(self.url("sendDocument"))
            .multipart(form)
            .send()
            .await
            .map_err(|e| TelegramError::Upload(format!("bot sendDocument: {}", self.redact(e))))?;
        let json: serde_json::Value = resp.json().await.map_err(|e| {
            TelegramError::Upload(format!("bot sendDocument decode: {}", self.redact(e)))
        })?;
        if json.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            let desc = json
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error");
            return Err(TelegramError::Upload(format!(
                "bot sendDocument failed: {desc}"
            )));
        }
        let message_id = json
            .get("result")
            .and_then(|r| r.get("message_id"))
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| TelegramError::Upload("bot sendDocument: no message_id".into()))?;
        Ok(UploadResult { message_id, size })
    }

    async fn download_block(&self, _message_id: i64) -> Result<DownloadResult> {
        // The Bot API cannot fetch a message by id; MultiTransport routes downloads to
        // the user's MTProto session instead.
        Err(TelegramError::Download(
            "bot-API transport does not serve downloads (handled by the MTProto session)".into(),
        ))
    }

    async fn list_topic_documents(
        &self,
        _group_id: i64,
        _topic_id: i64,
        _before_message_id: Option<i64>,
        _limit: usize,
    ) -> Result<Vec<DocumentInfo>> {
        Err(TelegramError::Download(
            "bot-API transport does not enumerate forum documents (handled by the MTProto session)"
                .into(),
        ))
    }

    async fn download_range(&self, _message_id: i64, _offset: u64, _len: u32) -> Result<Vec<u8>> {
        // Bots are upload-only: no MTProto `upload.GetFile`. MultiTransport's
        // failover routes ranged reads to the user's MTProto session instead.
        Err(TelegramError::Download(
            "bot-API transport does not serve ranged reads (handled by the MTProto session)".into(),
        ))
    }

    async fn download_tail(&self, _message_id: i64, _len: u32) -> Result<Vec<u8>> {
        Err(TelegramError::Download(
            "bot-API transport does not serve ranged reads (handled by the MTProto session)".into(),
        ))
    }

    async fn delete_message(&self, message_id: i64) -> Result<()> {
        let resp = self
            .client
            .post(self.url("deleteMessage"))
            .form(&[
                ("chat_id", self.chat_id.to_string()),
                ("message_id", message_id.to_string()),
            ])
            .send()
            .await
            .map_err(|e| TelegramError::Delete(format!("bot deleteMessage: {}", self.redact(e))))?;
        let json: serde_json::Value = resp.json().await.map_err(|e| {
            TelegramError::Delete(format!("bot deleteMessage decode: {}", self.redact(e)))
        })?;
        if json.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err(TelegramError::Delete(
                "bot deleteMessage failed (handled by the MTProto session)".into(),
            ))
        }
    }

    async fn delete_messages(&self, message_ids: &[i64]) -> Result<()> {
        for id in message_ids {
            self.delete_message(*id).await?;
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn sync_metadata(&self, data: &[u8]) -> Result<i64> {
        // Snapshots can ride the bot upload path too.
        self.upload_block(data, "snapshot.bin")
            .await
            .map(|r| r.message_id)
    }

    async fn fetch_metadata(&self, _message_id: i64) -> Result<Vec<u8>> {
        Err(TelegramError::Download(
            "bot-API transport does not serve metadata fetch (handled by the MTProto session)"
                .into(),
        ))
    }

    fn channel_ref(&self) -> Option<(i64, i64, i64)> {
        // Bot-API transports carry no MTProto access_hash; the group routing is via
        // chat_id. Report None so callers rely on the MTProto session's channel_ref.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::to_bot_api_chat_id;
    use super::BotApiTransport;
    use crate::client::BlockTransport;

    /// A token-shaped test value (not a real bot token).
    const TOKEN: &str = "123456789:AAFakeTokenForRedactionTest_0123456789";

    fn assert_no_token(e: &crate::error::TelegramError) {
        let shown = format!("{e}");
        let debug = format!("{e:?}");
        assert!(!shown.contains(TOKEN), "token leaked via Display: {shown}");
        assert!(!debug.contains(TOKEN), "token leaked via Debug: {debug}");
        assert!(
            !shown.contains("AAFakeToken") && !debug.contains("AAFakeToken"),
            "a token fragment leaked: {shown}"
        );
    }

    /// telegram-H3: reqwest's error Display embeds the request URL, and the Bot
    /// API puts the token in the URL path. A connect failure to an unroutable
    /// TEST-NET-1 address (RFC 5737) must not carry the token into the error —
    /// these errors are logged by MultiTransport and the FUSE upload worker.
    #[tokio::test]
    async fn unroutable_send_error_does_not_contain_the_token() {
        let t = BotApiTransport::with_api_base(TOKEN, 1, 2, "http://192.0.2.1:9");
        let e = t.upload_block(b"x", "f").await.expect_err("unroutable");
        assert_no_token(&e);
    }

    /// A refused connection (closed local port) — the fast send-error path, for
    /// both request sites.
    #[tokio::test]
    async fn refused_connection_error_does_not_contain_the_token() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let t = BotApiTransport::with_api_base(TOKEN, 1, 2, format!("http://127.0.0.1:{port}"));
        assert_no_token(&t.upload_block(b"x", "f").await.expect_err("refused"));
        assert_no_token(&t.delete_message(5).await.expect_err("refused"));
    }

    /// A server that answers 200 with a non-JSON body — the decode-error path,
    /// whose reqwest error also carries the URL.
    #[tokio::test]
    async fn decode_error_does_not_contain_the_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nnotjson",
                        )
                        .await;
                });
            }
        });
        let t = BotApiTransport::with_api_base(TOKEN, 1, 2, format!("http://{addr}"));
        assert_no_token(&t.upload_block(b"x", "f").await.expect_err("bad body"));
        assert_no_token(&t.delete_message(5).await.expect_err("bad body"));
    }

    /// A one-shot HTTP server answering every request with `status` + `body`,
    /// and recording the request lines it saw.
    async fn canned_server(
        status: &'static str,
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    seen.lock().unwrap().push(req);
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(reply.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), seen)
    }

    #[tokio::test]
    async fn get_me_parses_a_bot_identity_over_real_http() {
        let (base, seen) = canned_server(
            "200 OK",
            r#"{"ok":true,"result":{"id":123456789,"is_bot":true,"first_name":"s","username":"my_store_bot"}}"#,
        )
        .await;
        let me = super::get_me_at(&base, TOKEN).await.unwrap();
        assert_eq!(
            me,
            super::BotIdentity {
                id: 123456789,
                username: "my_store_bot".into()
            }
        );
        let req = seen.lock().unwrap().join("\n");
        assert!(req.starts_with(&format!("GET /bot{TOKEN}/getMe ")), "{req}");
    }

    #[tokio::test]
    async fn get_me_rejections_are_errors_without_the_token() {
        let (base, _) = canned_server(
            "401 Unauthorized",
            r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
        )
        .await;
        let e = super::get_me_at(&base, TOKEN).await.expect_err("401");
        assert!(e.to_string().contains("Unauthorized"), "{e}");
        assert_no_token(&e);

        let (base, _) = canned_server(
            "200 OK",
            r#"{"ok":true,"result":{"id":5,"is_bot":false,"first_name":"a person","username":"someone"}}"#,
        )
        .await;
        let e = super::get_me_at(&base, TOKEN).await.expect_err("not a bot");
        assert!(e.to_string().contains("not belong to a bot"), "{e}");

        let (base, _) =
            canned_server("200 OK", r#"{"ok":true,"result":{"id":5,"is_bot":true}}"#).await;
        let e = super::get_me_at(&base, TOKEN)
            .await
            .expect_err("no username");
        assert!(e.to_string().contains("no bot username"), "{e}");

        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let e = super::get_me_at(&format!("http://127.0.0.1:{port}"), TOKEN)
            .await
            .expect_err("refused");
        assert_no_token(&e);
    }

    #[tokio::test]
    async fn leave_chat_posts_the_bot_api_chat_id() {
        let (base, seen) = canned_server("200 OK", r#"{"ok":true,"result":true}"#).await;
        super::leave_chat_at(&base, TOKEN, 4320408240)
            .await
            .unwrap();
        let req = seen.lock().unwrap().join("\n");
        assert!(
            req.starts_with(&format!("POST /bot{TOKEN}/leaveChat ")),
            "{req}"
        );
        assert!(req.contains("chat_id=-1004320408240"), "{req}");

        let (base, _) = canned_server(
            "400 Bad Request",
            r#"{"ok":false,"description":"Bad Request: chat not found"}"#,
        )
        .await;
        let e = super::leave_chat_at(&base, TOKEN, 1)
            .await
            .expect_err("400");
        assert!(e.to_string().contains("chat not found"), "{e}");
        assert_no_token(&e);
    }

    #[test]
    fn converts_raw_group_id_to_bot_api_form() {
        assert_eq!(to_bot_api_chat_id(4320408240), -1004320408240);
        // Already-negative ids pass through.
        assert_eq!(to_bot_api_chat_id(-1004320408240), -1004320408240);
    }
}
