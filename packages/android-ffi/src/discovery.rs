//! 设备发现：组播 announce + HTTP register 双路，事件合并成一条 `discovery.device` 流。
//!
//! `StatefulDevice` / `DiscoveredDevice` 不是 serde 类型，映射是手写的（上游 FRB 层的
//! `api/discovery.rs` 同样手写，形状保持一致：`channels` 已按可用性/IPv6/最近确认排序）。
//! 注意 core 没有把通道标成 `NotReachable` 的公开入口（`store.rs` 里只有测试路径会写），
//! 所以"这条通道失败了"由宿主自己维护。

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use localsend::discovery::{
    self as ls, DeviceChannel, DeviceIdentity, DiscoveredDevice, DiscoveryConfig, DiscoveryEvent,
    HttpChannel, StatefulDevice,
};
use localsend::http::dto_v2::RegisterDtoV2;
use localsend::model::discovery::{DeviceType, ProtocolType};
use localsend::multicast::{DEFAULT_MULTICAST_GROUP, DEFAULT_MULTICAST_GROUP_V6, DEFAULT_PORT};
use localsend::util::interface::InterfaceFilter;
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot};

use crate::{bridge, runtime, state};

const EVENT_CHANNEL_CAPACITY: usize = 64;
const STOP_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn start(args: Value) -> Result<Value, String> {
    let identity = state::identity()?;
    // 遗留实例先停：分区反复进出时组播 socket 会绑不上（上游 RUNNING_DISCOVERY 同型守卫）
    stop_inner().await;

    let group = match args.get("group").and_then(Value::as_str) {
        Some(text) => text
            .parse::<Ipv4Addr>()
            .map_err(|error| error.to_string())?,
        None => DEFAULT_MULTICAST_GROUP,
    };
    let group_v6 = match args.get("groupV6").and_then(Value::as_str) {
        Some(text) => text.parse::<Ipv6Addr>().ok(),
        None => Some(DEFAULT_MULTICAST_GROUP_V6),
    };
    let port = args
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_PORT as u64) as u16;
    let timeout =
        Duration::from_millis(args.get("timeoutMs").and_then(Value::as_u64).unwrap_or(500));

    let (event_tx, mut event_rx) = mpsc::channel::<DiscoveryEvent>(EVENT_CHANNEL_CAPACITY);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let handle = ls::start(
        DiscoveryConfig {
            group,
            group_v6,
            port,
            interface_filter: InterfaceFilter::default(),
            device: identity.multicast_device(),
            identity: DeviceIdentity {
                cert_pem: identity.cert_pem.clone(),
                private_key_pem: identity.key_pem.clone(),
            },
            timeout,
            event_tx: Some(event_tx),
        },
        stop_rx,
    )
    .await;

    let multicast_error = handle.multicast_error().map(|error| error.to_string());
    let slot = Arc::new(state::DiscoverySlot {
        handle,
        stop: std::sync::Mutex::new(Some(stop_tx)),
    });
    *state::DISCOVERY.lock().unwrap() = Some(slot.clone());
    runtime::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                DiscoveryEvent::Discovered { device } | DiscoveryEvent::Updated { device } => {
                    // 每次吐合并后的整设备状态（上游 listen 的语义），宿主按 fingerprint upsert
                    bridge::emit(
                        "discovery.device",
                        device_json(&slot.handle, Some(&device.fingerprint)),
                    );
                }
                DiscoveryEvent::MulticastFailed => {
                    // 组播 socket 被系统作废：宿主要重启 discovery（并重新持组播锁）
                    bridge::emit(
                        "discovery.multicastFailed",
                        json!({ "error": "multicast sockets failed" }),
                    );
                }
            }
        }
    });

    Ok(json!({ "multicastError": multicast_error }))
}

pub async fn stop() -> Value {
    stop_inner().await;
    json!({})
}

async fn stop_inner() {
    let slot = { state::DISCOVERY.lock().unwrap().take() };
    let Some(slot) = slot else { return };
    if let Some(stop_tx) = slot.stop.lock().unwrap().take() {
        let _ = stop_tx.send(());
    }
    let _ = tokio::time::timeout(STOP_TIMEOUT, slot.handle.wait_stopped()).await;
}

/// 对方向我方 `register` 也算一次确认：回喂 store，否则"别人看得见我、我看不见别人"。
/// 自己 announce 的回环按指纹丢掉。
pub fn confirm(ip: String, info: &RegisterDtoV2) {
    let Some(slot) = state::discovery_slot() else {
        return;
    };
    let Ok(own) = state::identity() else { return };
    if info.fingerprint == own.fingerprint {
        return;
    }
    let device = DiscoveredDevice {
        alias: info.alias.clone(),
        version: info.version.clone(),
        device_model: info.device_model.clone(),
        device_type: info.device_type.clone(),
        fingerprint: info.fingerprint.clone(),
        channel: DeviceChannel::Http(HttpChannel {
            host: ip,
            port: info.port,
            protocol: info.protocol,
        }),
        download: info.download,
    };
    runtime::spawn(async move {
        let _ = slot.handle.add_device(device).await;
    });
}

pub async fn announce() -> Result<Value, String> {
    let slot = state::discovery_slot().ok_or("discovery.start has not been called")?;
    slot.handle.announce().await;
    Ok(json!({}))
}

pub async fn discover_staged(args: &Value) -> Result<Value, String> {
    let slot = state::discovery_slot().ok_or("discovery.start has not been called")?;
    let port = args
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_PORT as u64) as u16;
    let protocol = parse_protocol(args.get("protocol").and_then(Value::as_str));
    let grace = Duration::from_millis(args.get("graceMs").and_then(Value::as_u64).unwrap_or(1000));
    let interface_ips: Vec<Ipv4Addr> = string_array(args, "interfaceIps")
        .into_iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    let known: Vec<HttpChannel> = object_array(args, "knownChannels")
        .iter()
        .filter_map(http_channel_of)
        .collect();

    slot.handle
        .discover_staged(known, interface_ips, port, protocol, grace)
        .await
        .map_err(|error| error.to_string())?;
    Ok(device_json(&slot.handle, None))
}

pub fn add_device(args: &Value) -> Result<Value, String> {
    let slot = state::discovery_slot().ok_or("discovery.start has not been called")?;
    let device = args
        .get("device")
        .and_then(Value::as_object)
        .ok_or("device is required")?;
    let channel = device
        .get("channel")
        .and_then(http_channel_of)
        .map(DeviceChannel::Http)
        .ok_or("device.channel is required")?;
    let parsed = DiscoveredDevice {
        alias: string_in(device, "alias").unwrap_or_default(),
        version: string_in(device, "version").unwrap_or_default(),
        device_model: string_in(device, "deviceModel"),
        device_type: string_in(device, "deviceType").map(|value| parse_device_type(&value)),
        fingerprint: string_in(device, "fingerprint").ok_or("device.fingerprint is required")?,
        channel,
        download: device
            .get("download")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    runtime::spawn(async move {
        let _ = slot.handle.add_device(parsed).await;
    });
    Ok(json!({ "added": true }))
}

pub fn devices() -> Result<Value, String> {
    let slot = state::discovery_slot().ok_or("discovery.start has not been called")?;
    Ok(device_json(&slot.handle, None))
}

pub fn device_by_fingerprint(fingerprint: &str) -> Value {
    match state::discovery_slot() {
        Some(slot) => device_json(&slot.handle, Some(fingerprint)),
        None => Value::Null,
    }
}

fn device_json(handle: &ls::DiscoveryHandle, fingerprint: Option<&str>) -> Value {
    let all: Vec<StatefulDevice> = handle.devices();
    let mapped: Vec<Value> = all
        .iter()
        .filter(|stored| fingerprint.is_none_or(|want| stored.device.fingerprint == want))
        .map(stored_json)
        .collect();
    match fingerprint {
        Some(_) => mapped.into_iter().next().unwrap_or(Value::Null),
        None => Value::Array(mapped),
    }
}

fn stored_json(stored: &StatefulDevice) -> Value {
    let device = &stored.device;
    let channels: Vec<Value> = stored
        .get_ranked_channels()
        .into_iter()
        .map(|channel| {
            let status = stored
                .channels
                .get(channel)
                .map(|status| format!("{status:?}"))
                .unwrap_or_else(|| "Available".to_string());
            let mut value = match channel_json(channel) {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            value.insert("status".to_string(), Value::String(status));
            Value::Object(value)
        })
        .collect();
    json!({
        "fingerprint": device.fingerprint,
        "alias": device.alias,
        "version": device.version,
        "deviceModel": device.device_model,
        "deviceType": device.device_type.as_ref().map(|kind| format!("{kind:?}")),
        "download": device.download,
        "bestChannel": stored.get_best_channel().map(channel_json),
        "channels": channels,
        "lastSeenMs": last_seen_ms(stored),
    })
}

fn channel_json(channel: &DeviceChannel) -> Value {
    match channel {
        DeviceChannel::Http(http) => json!({
            "host": http.host,
            "port": http.port,
            "protocol": format!("{:?}", http.protocol),
        }),
    }
}

fn http_channel_of(value: &Value) -> Option<HttpChannel> {
    let object = value.as_object()?;
    Some(HttpChannel {
        host: string_in(object, "host")?,
        port: object.get("port").and_then(Value::as_u64)? as u16,
        protocol: parse_protocol(string_in(object, "protocol").as_deref()),
    })
}

/// 设备最后一次被确认的时间：core 把日志按序留着，最后一条即最近出现。
fn last_seen_ms(stored: &StatefulDevice) -> Option<u64> {
    stored
        .logs
        .last()
        .and_then(|log| log.timestamp.duration_since(UNIX_EPOCH).ok())
        .map(|since| since.as_millis() as u64)
}

fn parse_protocol(value: Option<&str>) -> ProtocolType {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("http") => ProtocolType::Http,
        _ => ProtocolType::Https,
    }
}

fn parse_device_type(value: &str) -> DeviceType {
    match value.to_ascii_uppercase().as_str() {
        "DESKTOP" => DeviceType::Desktop,
        "WEB" => DeviceType::Web,
        "HEADLESS" => DeviceType::Headless,
        "SERVER" => DeviceType::Server,
        _ => DeviceType::Mobile,
    }
}

fn string_in(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

fn string_array(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn object_array(args: &Value, key: &str) -> Vec<Value> {
    args.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
