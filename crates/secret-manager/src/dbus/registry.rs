//! Register and unregister collection, alias, and item objects; shared notifications.

use super::collection::{Collection, CollectionRef};
use super::item::Item;
use super::paths;
use super::service::ServiceSignals;
use super::state::Shared;
use zbus::Connection;
use zbus::object_server::SignalEmitter;

pub async fn register_collection(conn: &Connection, state: &Shared, id: &str) -> zbus::Result<()> {
    let server = conn.object_server();
    server
        .at(
            paths::collection(id),
            Collection::new(state.clone(), CollectionRef::Id(id.to_string())),
        )
        .await?;
    let item_ids = state
        .lock()
        .await
        .collections
        .get(id)
        .map(|v| v.item_ids())
        .unwrap_or_default();
    for iid in item_ids {
        server
            .at(
                paths::item(id, &iid),
                Item::new(state.clone(), id.to_string(), iid),
            )
            .await?;
    }
    Ok(())
}

pub async fn unregister_collection(conn: &Connection, id: &str, item_ids: &[String]) {
    let server = conn.object_server();
    for iid in item_ids {
        let _ = server.remove::<Item, _>(paths::item(id, iid)).await;
    }
    let _ = server.remove::<Collection, _>(paths::collection(id)).await;
}

/// Idempotent: an alias object resolves its target at call time, so it is
/// registered once and never removed.
pub async fn register_alias(conn: &Connection, state: &Shared, name: &str) -> zbus::Result<()> {
    if let Some(path) = paths::alias(name) {
        conn.object_server()
            .at(
                path,
                Collection::new(state.clone(), CollectionRef::Alias(name.to_string())),
            )
            .await?;
    }
    Ok(())
}

pub async fn register_item(
    conn: &Connection,
    state: &Shared,
    collection_id: &str,
    item_id: &str,
) -> zbus::Result<()> {
    conn.object_server()
        .at(
            paths::item(collection_id, item_id),
            Item::new(
                state.clone(),
                collection_id.to_string(),
                item_id.to_string(),
            ),
        )
        .await?;
    Ok(())
}

pub async fn register_all(conn: &Connection, state: &Shared) -> zbus::Result<()> {
    let (ids, aliases) = {
        let st = state.lock().await;
        (
            st.collections.keys().cloned().collect::<Vec<_>>(),
            st.aliases.keys().cloned().collect::<Vec<_>>(),
        )
    };
    for id in ids {
        register_collection(conn, state, &id).await?;
    }
    for name in aliases {
        register_alias(conn, state, &name).await?;
    }
    Ok(())
}

/// `Service.CollectionChanged` plus `PropertiesChanged` for `Collection.Locked`.
pub async fn notify_collection_changed(conn: &Connection, id: &str) {
    if let Ok(emitter) = SignalEmitter::new(conn, paths::SERVICE_PATH) {
        let _ = emitter.collection_changed(paths::collection(id)).await;
    }
    if let Ok(iface) = conn
        .object_server()
        .interface::<_, Collection>(paths::collection(id))
        .await
    {
        let _ = iface
            .get()
            .await
            .locked_changed(iface.signal_emitter())
            .await;
    }
}
