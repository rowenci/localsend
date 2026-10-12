//! 本机身份：自签证书 + 指纹，持久化在宿主私有目录。
//!
//! 私钥只在 Rust 侧存在，从不过 JNI 边界（`identity.load` 只回指纹）。
//! 落盘格式是本 crate 自己的 `identity.json`（字段名沿用上游 `StoredSecurityContext`
//! 的 camelCase 语义），不复用 CLI 的 `identity.pem` —— 那样要额外引 `pem`/`rcgen`
//! 两个依赖来重新解析 PEM，而 `generate_self_signed()` 本来就把四段都给我们了。

use std::path::PathBuf;

use localsend::crypto::cert::generate_self_signed;
use localsend::http::dto_v2::RegisterDtoV2;
use localsend::http::server::TlsConfig;
use localsend::http::state::ClientInfo;
use localsend::model::discovery::{DeviceType, PROTOCOL_VERSION_V2, ProtocolType};
use localsend::multicast::MulticastDevice;
use serde::{Deserialize, Serialize};

/// 一台设备在协议里的全部身份材料。
pub struct Identity {
    pub alias: String,
    pub port: u16,
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
    pub device_model: String,
    pub device_type: DeviceType,
}

pub struct IdentityConfig {
    pub data_dir: PathBuf,
    pub alias: String,
    pub port: u16,
    pub device_model: String,
    pub device_type: DeviceType,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredIdentity {
    private_key: String,
    public_key: String,
    certificate: String,
    certificate_hash: String,
}

impl Identity {
    /// 读取已有身份；不存在时生成一份并落盘。第二个返回值表示本次是否新生成。
    pub fn load_or_generate(config: &IdentityConfig) -> anyhow::Result<(Identity, bool)> {
        std::fs::create_dir_all(&config.data_dir)?;
        let path = config.data_dir.join("identity.json");
        let (stored, generated) = match std::fs::read_to_string(&path) {
            Ok(text) => (serde_json::from_str::<StoredIdentity>(&text)?, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let cert = generate_self_signed()?;
                let stored = StoredIdentity {
                    private_key: cert.private_key_pem.clone(),
                    public_key: cert.public_key_pem.clone(),
                    certificate: cert.certificate_pem.clone(),
                    certificate_hash: cert.fingerprint.clone(),
                };
                write_private(&path, &serde_json::to_string(&stored)?)?;
                (stored, true)
            }
            Err(error) => return Err(error.into()),
        };
        let identity = Identity {
            alias: config.alias.clone(),
            port: config.port,
            cert_pem: stored.certificate,
            key_pem: stored.private_key,
            fingerprint: stored.certificate_hash,
            device_model: config.device_model.clone(),
            device_type: config.device_type.clone(),
        };
        Ok((identity, generated))
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            cert: self.cert_pem.clone(),
            private_key: self.key_pem.clone(),
        }
    }

    pub fn client_info(&self) -> ClientInfo {
        ClientInfo {
            alias: self.alias.clone(),
            version: PROTOCOL_VERSION_V2.to_string(),
            device_model: Some(self.device_model.clone()),
            device_type: Some(self.device_type.clone()),
            token: self.fingerprint.clone(),
        }
    }

    pub fn register_dto(&self) -> RegisterDtoV2 {
        RegisterDtoV2 {
            alias: self.alias.clone(),
            version: PROTOCOL_VERSION_V2.to_string(),
            device_model: Some(self.device_model.clone()),
            device_type: Some(self.device_type.clone()),
            fingerprint: self.fingerprint.clone(),
            port: self.port,
            protocol: ProtocolType::Https,
            download: false,
        }
    }

    pub fn multicast_device(&self) -> MulticastDevice {
        MulticastDevice {
            alias: self.alias.clone(),
            version: PROTOCOL_VERSION_V2.to_string(),
            device_model: Some(self.device_model.clone()),
            device_type: Some(self.device_type.clone()),
            fingerprint: self.fingerprint.clone(),
            port: self.port,
            protocol: ProtocolType::Https,
            download: false,
        }
    }
}

/// `identity.load` 的参数解析（缺字段就同步报参数错，不占一次 reply 往返）
pub fn config_from(args: &serde_json::Value) -> Result<IdentityConfig, String> {
    use crate::state::ValueExt as _;
    let data_dir = args.string("dataDir").ok_or("dataDir is required")?;
    let alias = args.string("alias").ok_or("alias is required")?;
    Ok(IdentityConfig {
        data_dir: std::path::PathBuf::from(data_dir),
        alias,
        port: args.u64_at("port", 53317) as u16,
        device_model: args
            .string("deviceModel")
            .unwrap_or_else(|| "Android".to_string()),
        device_type: parse_device_type(args.string("deviceType").as_deref()),
    })
}

/// 载入或生成身份。RSA-2048 生成是 bignum-heavy（根 Cargo.toml 特意给它开 opt-level=2），
/// 所以放 blocking 线程跑，别占着 tokio worker。
pub async fn load(config: IdentityConfig) -> Result<serde_json::Value, String> {
    let (identity, generated) =
        tokio::task::spawn_blocking(move || Identity::load_or_generate(&config))
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
    crate::state::set_identity(std::sync::Arc::new(identity));
    let shared = crate::state::identity()?;
    Ok(serde_json::json!({
        "fingerprint": shared.fingerprint,
        "generated": generated,
        "alias": shared.alias,
        "port": shared.port,
    }))
}

/// `DeviceType` 的线上名是 SCREAMING_SNAKE_CASE，宿主传错了退化成 Mobile 而不是崩。
pub fn parse_device_type(value: Option<&str>) -> DeviceType {
    match value.map(|v| v.to_ascii_uppercase()).as_deref() {
        Some("DESKTOP") => DeviceType::Desktop,
        Some("WEB") => DeviceType::Web,
        Some("HEADLESS") => DeviceType::Headless,
        Some("SERVER") => DeviceType::Server,
        _ => DeviceType::Mobile,
    }
}

fn write_private(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // 文件里是私钥：只允许属主读写，且绝不覆盖已有身份（覆盖等于把设备变成"新设备"）
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: std::path::PathBuf) -> IdentityConfig {
        IdentityConfig {
            data_dir: dir,
            alias: "Test".to_string(),
            port: 53317,
            device_model: "Pixel".to_string(),
            device_type: DeviceType::Mobile,
        }
    }

    #[test]
    fn generates_once_and_reuses_the_same_fingerprint() {
        let dir = std::env::temp_dir().join(format!("ls-identity-{}", uuid_like()));
        let (first, generated_first) = Identity::load_or_generate(&config(dir.clone())).unwrap();
        let (second, generated_second) = Identity::load_or_generate(&config(dir.clone())).unwrap();
        assert!(generated_first);
        assert!(!generated_second);
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.cert_pem, second.cert_pem);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_uppercase_hex_sha256() {
        let dir = std::env::temp_dir().join(format!("ls-identity-fp-{}", uuid_like()));
        let (identity, _) = Identity::load_or_generate(&config(dir.clone())).unwrap();
        assert_eq!(identity.fingerprint.len(), 64);
        assert!(
            identity
                .fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn derived_dto_carries_port_and_protocol() {
        let dir = std::env::temp_dir().join(format!("ls-identity-dto-{}", uuid_like()));
        let (identity, _) = Identity::load_or_generate(&config(dir.clone())).unwrap();
        let dto = identity.register_dto();
        assert_eq!(dto.port, 53317);
        assert_eq!(dto.version, PROTOCOL_VERSION_V2);
        assert_eq!(dto.fingerprint, identity.fingerprint);
        assert_eq!(identity.client_info().token, identity.fingerprint);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_device_type_falls_back_to_mobile() {
        assert_eq!(parse_device_type(Some("desktop")), DeviceType::Desktop);
        assert_eq!(parse_device_type(Some("nonsense")), DeviceType::Mobile);
        assert_eq!(parse_device_type(None), DeviceType::Mobile);
    }

    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
