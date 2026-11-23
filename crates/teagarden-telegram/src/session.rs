use std::collections::HashMap;
use std::net::AddrParseError;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use grammers_session::types::{
    ChannelKind, ChannelState, DcOption, PeerAuth, PeerId, PeerInfo, PeerKind, UpdateState,
    UpdatesState,
};
use grammers_session::{BoxFuture, Session, SessionData};
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA_VERSION: i64 = 1;

const USER_SELF: i64 = 1;
const USER_BOT: i64 = 2;
const USER_SELF_BOT: i64 = 3;
const CHANNEL_MEGAGROUP: i64 = 4;
const CHANNEL_BROADCAST: i64 = 8;
const CHANNEL_GIGAGROUP: i64 = 12;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SqliteSessionError {
    #[error("session lock is poisoned")]
    Poisoned,
    #[error("session database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("session file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid datacenter socket address: {0}")]
    AddrParse(#[from] AddrParseError),
    #[error("invalid auth_key length: expected 256, got {0}")]
    InvalidAuthKeyLength(usize),
    #[error("invalid persisted Telegram peer id {0}")]
    InvalidPeerId(i64),
    #[error("unsupported session schema version {0}")]
    UnsupportedVersion(i64),
}

struct Cache {
    home_dc: i32,
    dc_options: HashMap<i32, DcOption>,
}

/// Grammers 0.10 session storage on TeaGarden's existing rusqlite runtime.
///
/// Upstream's optional `SqliteSession` uses libSQL, whose bundled SQLite cannot
/// coexist in one executable with TeaGarden's bundled rusqlite. This adapter
/// implements the same public `Session` contract and schema without linking a
/// second SQLite implementation.
pub(crate) struct SqliteSession {
    database: Mutex<Connection>,
    cache: Mutex<Cache>,
}

impl SqliteSession {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, SqliteSessionError> {
        let path = path.as_ref();
        if path != Path::new(":memory:") {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                options.mode(0o600);
                let file = options.open(path)?;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            #[cfg(not(unix))]
            {
                options.open(path)?;
            }
        }

        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )?;

        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0 => Self::create_schema(&mut connection)?,
            SCHEMA_VERSION => {}
            other => return Err(SqliteSessionError::UnsupportedVersion(other)),
        }

        let defaults = SessionData::default();
        let home_dc = connection
            .query_row("SELECT dc_id FROM dc_home LIMIT 1", [], |row| row.get(0))
            .optional()?
            .unwrap_or(defaults.home_dc);

        let mut dc_options = defaults.dc_options;
        {
            let mut statement = connection
                .prepare("SELECT dc_id, ipv4, ipv6, auth_key FROM dc_option ORDER BY dc_id")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?;
            for row in rows {
                let (id, ipv4, ipv6, auth_key) = row?;
                let auth_key = match auth_key {
                    Some(bytes) => Some(bytes.try_into().map_err(|bytes: Vec<u8>| {
                        SqliteSessionError::InvalidAuthKeyLength(bytes.len())
                    })?),
                    None => None,
                };
                dc_options.insert(
                    id,
                    DcOption {
                        id,
                        ipv4: ipv4.parse()?,
                        ipv6: ipv6.parse()?,
                        auth_key,
                    },
                );
            }
        }

        Ok(Self {
            database: Mutex::new(connection),
            cache: Mutex::new(Cache {
                home_dc,
                dc_options,
            }),
        })
    }

    fn create_schema(connection: &mut Connection) -> Result<(), SqliteSessionError> {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE dc_home (
                 dc_id INTEGER NOT NULL PRIMARY KEY
             );
             CREATE TABLE dc_option (
                 dc_id INTEGER NOT NULL PRIMARY KEY,
                 ipv4 TEXT NOT NULL,
                 ipv6 TEXT NOT NULL,
                 auth_key BLOB
             );
             CREATE TABLE peer_info (
                 peer_id INTEGER NOT NULL PRIMARY KEY,
                 hash INTEGER,
                 subtype INTEGER
             );
             CREATE TABLE update_state (
                 pts INTEGER NOT NULL,
                 qts INTEGER NOT NULL,
                 date INTEGER NOT NULL,
                 seq INTEGER NOT NULL
             );
             CREATE TABLE channel_state (
                 peer_id INTEGER NOT NULL PRIMARY KEY,
                 pts INTEGER NOT NULL
             );
             PRAGMA user_version = 1;",
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn database(&self) -> Result<MutexGuard<'_, Connection>, SqliteSessionError> {
        self.database
            .lock()
            .map_err(|_| SqliteSessionError::Poisoned)
    }

    fn cache(&self) -> Result<MutexGuard<'_, Cache>, SqliteSessionError> {
        self.cache.lock().map_err(|_| SqliteSessionError::Poisoned)
    }

    fn peer_from_row(
        peer_id: i64,
        hash: Option<i64>,
        subtype: Option<i64>,
    ) -> Result<PeerInfo, SqliteSessionError> {
        let peer = PeerId::from_bot_api_dialog_id(peer_id)
            .ok_or(SqliteSessionError::InvalidPeerId(peer_id))?;
        let bare = peer
            .bare_id()
            .ok_or(SqliteSessionError::InvalidPeerId(peer_id))?;
        Ok(match peer.kind() {
            PeerKind::User => PeerInfo::User {
                id: bare,
                auth: hash.map(PeerAuth::from_hash),
                bot: subtype.map(|value| value & USER_BOT != 0),
                is_self: subtype.map(|value| value & USER_SELF != 0),
            },
            PeerKind::Chat => PeerInfo::Chat { id: bare },
            PeerKind::Channel => PeerInfo::Channel {
                id: bare,
                auth: hash.map(PeerAuth::from_hash),
                kind: subtype.and_then(|value| {
                    if value & CHANNEL_GIGAGROUP == CHANNEL_GIGAGROUP {
                        Some(ChannelKind::Gigagroup)
                    } else if value & CHANNEL_BROADCAST != 0 {
                        Some(ChannelKind::Broadcast)
                    } else if value & CHANNEL_MEGAGROUP != 0 {
                        Some(ChannelKind::Megagroup)
                    } else {
                        None
                    }
                }),
            },
        })
    }

    fn read_updates(connection: &Connection) -> Result<UpdatesState, SqliteSessionError> {
        let mut state = connection
            .query_row(
                "SELECT pts, qts, date, seq FROM update_state LIMIT 1",
                [],
                |row| {
                    Ok(UpdatesState {
                        pts: row.get(0)?,
                        qts: row.get(1)?,
                        date: row.get(2)?,
                        seq: row.get(3)?,
                        channels: Vec::new(),
                    })
                },
            )
            .optional()?
            .unwrap_or_default();
        let mut statement =
            connection.prepare("SELECT peer_id, pts FROM channel_state ORDER BY peer_id")?;
        state.channels = statement
            .query_map([], |row| {
                Ok(ChannelState {
                    id: row.get(0)?,
                    pts: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(state)
    }
}

impl Session for SqliteSession {
    type Error = SqliteSessionError;

    fn home_dc_id(&self) -> Result<i32, Self::Error> {
        Ok(self.cache()?.home_dc)
    }

    fn set_home_dc_id(&self, dc_id: i32) -> BoxFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut connection = self.database()?;
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM dc_home", [])?;
            transaction.execute("INSERT INTO dc_home (dc_id) VALUES (?1)", [dc_id])?;
            transaction.commit()?;
            self.cache()?.home_dc = dc_id;
            Ok(())
        })
    }

    fn dc_option(&self, dc_id: i32) -> Result<Option<DcOption>, Self::Error> {
        Ok(self.cache()?.dc_options.get(&dc_id).cloned())
    }

    fn set_dc_option(&self, dc_option: &DcOption) -> BoxFuture<'_, Result<(), Self::Error>> {
        let dc_option = dc_option.clone();
        Box::pin(async move {
            self.database()?.execute(
                "INSERT OR REPLACE INTO dc_option (dc_id, ipv4, ipv6, auth_key)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    dc_option.id,
                    dc_option.ipv4.to_string(),
                    dc_option.ipv6.to_string(),
                    dc_option.auth_key.map(|key| key.to_vec()),
                ],
            )?;
            self.cache()?.dc_options.insert(dc_option.id, dc_option);
            Ok(())
        })
    }

    fn peer(&self, peer: PeerId) -> BoxFuture<'_, Result<Option<PeerInfo>, Self::Error>> {
        Box::pin(async move {
            let connection = self.database()?;
            let row = if let Some(peer_id) = peer.bot_api_dialog_id() {
                connection
                    .query_row(
                        "SELECT peer_id, hash, subtype FROM peer_info WHERE peer_id = ?1 LIMIT 1",
                        [peer_id],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Option<i64>>(1)?,
                                row.get::<_, Option<i64>>(2)?,
                            ))
                        },
                    )
                    .optional()?
            } else {
                connection
                    .query_row(
                        "SELECT peer_id, hash, subtype FROM peer_info
                         WHERE subtype & ?1 != 0 LIMIT 1",
                        [USER_SELF],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Option<i64>>(1)?,
                                row.get::<_, Option<i64>>(2)?,
                            ))
                        },
                    )
                    .optional()?
            };
            row.map(|(id, hash, subtype)| Self::peer_from_row(id, hash, subtype))
                .transpose()
        })
    }

    fn cache_peer(&self, peer: &PeerInfo) -> BoxFuture<'_, Result<(), Self::Error>> {
        let peer = peer.clone();
        Box::pin(async move {
            let peer = if let Some(mut existing) = self.peer(peer.id()).await? {
                existing.extend_info(&peer);
                existing
            } else {
                peer
            };
            let peer_id = peer
                .id()
                .bot_api_dialog_id()
                .ok_or(SqliteSessionError::InvalidPeerId(0))?;
            let hash = peer.auth().map(PeerAuth::hash);
            let subtype = match &peer {
                PeerInfo::User { bot, is_self, .. } => {
                    match (bot.unwrap_or_default(), is_self.unwrap_or_default()) {
                        (true, true) => Some(USER_SELF_BOT),
                        (true, false) => Some(USER_BOT),
                        (false, true) => Some(USER_SELF),
                        (false, false) => None,
                    }
                }
                PeerInfo::Chat { .. } => None,
                PeerInfo::Channel { kind, .. } => kind.map(|kind| match kind {
                    ChannelKind::Megagroup => CHANNEL_MEGAGROUP,
                    ChannelKind::Broadcast => CHANNEL_BROADCAST,
                    ChannelKind::Gigagroup => CHANNEL_GIGAGROUP,
                }),
            };
            self.database()?.execute(
                "INSERT OR REPLACE INTO peer_info (peer_id, hash, subtype) VALUES (?1, ?2, ?3)",
                params![peer_id, hash, subtype],
            )?;
            Ok(())
        })
    }

    fn updates_state(&self) -> BoxFuture<'_, Result<UpdatesState, Self::Error>> {
        Box::pin(async move {
            let connection = self.database()?;
            Self::read_updates(&connection)
        })
    }

    fn set_update_state(&self, update: UpdateState) -> BoxFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut connection = self.database()?;
            let mut state = Self::read_updates(&connection)?;
            match update {
                UpdateState::All(new_state) => state = new_state,
                UpdateState::Primary { pts, date, seq } => {
                    state.pts = pts;
                    state.date = date;
                    state.seq = seq;
                }
                UpdateState::Secondary { qts } => state.qts = qts,
                UpdateState::Channel { id, pts } => {
                    state.channels.retain(|channel| channel.id != id);
                    state.channels.push(ChannelState { id, pts });
                }
            }

            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM update_state", [])?;
            transaction.execute(
                "INSERT INTO update_state (pts, qts, date, seq) VALUES (?1, ?2, ?3, ?4)",
                params![state.pts, state.qts, state.date, state.seq],
            )?;
            transaction.execute("DELETE FROM channel_state", [])?;
            for channel in state.channels {
                transaction.execute(
                    "INSERT INTO channel_state (peer_id, pts) VALUES (?1, ?2)",
                    params![channel.id, channel.pts],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom_dc_option(id: i32) -> DcOption {
        DcOption {
            id,
            ipv4: "127.0.0.1:443".parse().unwrap(),
            ipv6: "[::1]:443".parse().unwrap(),
            auth_key: Some([id as u8; 256]),
        }
    }

    #[tokio::test]
    async fn session_state_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telegram.session");
        let default_dc = SessionData::default().home_dc;

        {
            let session = SqliteSession::open(&path).unwrap();
            session.set_home_dc_id(default_dc + 1).await.unwrap();
            session
                .cache_peer(&PeerInfo::User {
                    id: 42,
                    auth: Some(PeerAuth::from_hash(7)),
                    bot: Some(false),
                    is_self: Some(true),
                })
                .await
                .unwrap();
            session
                .set_update_state(UpdateState::Channel { id: 99, pts: 12 })
                .await
                .unwrap();
        }

        let reopened = SqliteSession::open(&path).unwrap();
        assert_eq!(reopened.home_dc_id().unwrap(), default_dc + 1);
        assert!(reopened.peer(PeerId::self_user()).await.unwrap().is_some());
        assert_eq!(
            reopened.updates_state().await.unwrap().channels,
            vec![ChannelState { id: 99, pts: 12 }]
        );
        assert_eq!(&std::fs::read(&path).unwrap()[..16], b"SQLite format 3\0");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telegram.session");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);

        let error = SqliteSession::open(&path)
            .err()
            .expect("unknown schemas must fail closed");
        assert!(error.to_string().contains("version 99"));
    }

    #[tokio::test]
    async fn datacenter_auth_key_survives_reopen_and_malformed_keys_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telegram.session");
        let dc_option = custom_dc_option(99);

        let session = SqliteSession::open(&path).unwrap();
        session.set_dc_option(&dc_option).await.unwrap();
        assert_eq!(
            session.dc_option(dc_option.id).unwrap(),
            Some(dc_option.clone())
        );
        drop(session);

        let reopened = SqliteSession::open(&path).unwrap();
        assert_eq!(reopened.dc_option(dc_option.id).unwrap(), Some(dc_option));
        drop(reopened);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE dc_option SET auth_key = ?1 WHERE dc_id = 99",
                [vec![0u8; 255]],
            )
            .unwrap();
        drop(connection);

        let error = SqliteSession::open(&path)
            .err()
            .expect("malformed permanent auth keys must fail closed");
        assert!(matches!(
            error,
            SqliteSessionError::InvalidAuthKeyLength(255)
        ));
    }

    #[tokio::test]
    async fn all_peer_kinds_and_subtypes_round_trip() {
        let session = SqliteSession::open(":memory:").unwrap();
        let peers = [
            PeerInfo::User {
                id: 41,
                auth: Some(PeerAuth::from_hash(-7)),
                bot: Some(true),
                is_self: Some(true),
            },
            PeerInfo::Chat { id: 42 },
            PeerInfo::Channel {
                id: 43,
                auth: Some(PeerAuth::from_hash(8)),
                kind: Some(ChannelKind::Megagroup),
            },
            PeerInfo::Channel {
                id: 44,
                auth: Some(PeerAuth::from_hash(9)),
                kind: Some(ChannelKind::Broadcast),
            },
            PeerInfo::Channel {
                id: 45,
                auth: Some(PeerAuth::from_hash(10)),
                kind: Some(ChannelKind::Gigagroup),
            },
        ];

        for peer in &peers {
            session.cache_peer(peer).await.unwrap();
            assert_eq!(session.peer(peer.id()).await.unwrap(), Some(peer.clone()));
        }
        assert_eq!(
            session.peer(PeerId::self_user()).await.unwrap(),
            Some(peers[0].clone())
        );
    }

    #[tokio::test]
    async fn partial_update_state_changes_preserve_unrelated_fields() {
        let session = SqliteSession::open(":memory:").unwrap();
        session
            .set_update_state(UpdateState::All(UpdatesState {
                pts: 1,
                qts: 2,
                date: 3,
                seq: 4,
                channels: vec![
                    ChannelState { id: 5, pts: 6 },
                    ChannelState { id: 7, pts: 8 },
                ],
            }))
            .await
            .unwrap();
        session
            .set_update_state(UpdateState::Primary {
                pts: 11,
                date: 12,
                seq: 13,
            })
            .await
            .unwrap();
        session
            .set_update_state(UpdateState::Secondary { qts: 14 })
            .await
            .unwrap();
        session
            .set_update_state(UpdateState::Channel { id: 7, pts: 15 })
            .await
            .unwrap();

        assert_eq!(
            session.updates_state().await.unwrap(),
            UpdatesState {
                pts: 11,
                qts: 14,
                date: 12,
                seq: 13,
                channels: vec![
                    ChannelState { id: 5, pts: 6 },
                    ChannelState { id: 7, pts: 15 },
                ],
            }
        );
    }
}
