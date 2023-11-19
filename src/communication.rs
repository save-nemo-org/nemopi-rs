use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use log::{debug, info};
use rumqttc::{Client, Connection, MqttOptions, QoS, Transport};
use sha2::Sha256;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

fn parse_connection_string(connection_string: String) -> (String, String, String) {
    debug!("Parsing connection string: {connection_string}");

    let mut hostname = None;
    let mut key = None;
    let mut device_id = None;

    let parts: Vec<&str> = connection_string.split(';').collect();
    for p in parts {
        if p.starts_with("HostName=") {
            hostname = p.strip_prefix("HostName=");
        } else if p.starts_with("DeviceId=") {
            device_id = p.strip_prefix("DeviceId=");
        } else if p.starts_with("SharedAccessKey=") {
            key = p.strip_prefix("SharedAccessKey=");
        }
    }
    debug!("hostname: {hostname:?}");
    debug!("device_id: {device_id:?}");
    debug!("shared access key: {key:?}");

    (
        hostname.unwrap().into(),
        device_id.unwrap().into(),
        key.unwrap().into(),
    )
}

fn generate_token(decoded_key: &Vec<u8>, message: &str) -> String {
    // Checked base64 and hmac in new so should be safe to unwrap here
    let mut mac = Hmac::<Sha256>::new_from_slice(decoded_key).unwrap();
    mac.update(message.as_bytes());
    let mac_result = mac.finalize();
    let signature = general_purpose::STANDARD.encode(mac_result.into_bytes());

    let pairs = &vec![("sig", signature)];
    serde_urlencoded::to_string(pairs).unwrap()
}

fn generate_username(hostname: &str, device_id: &str) -> String {
    format!("{hostname}/{device_id}/?api-version=2021-04-12")
}

fn generate_shared_access_signature(
    hostname: &str,
    device_id: &str,
    key: &str,
    expiry: &DateTime<Utc>,
) -> String {
    // Verify key is base64
    let decoded_key = general_purpose::STANDARD
        .decode(key)
        .expect("Invalid base64 key");

    // Verify key is the right length for Hmac
    Hmac::<Sha256>::new_from_slice(&decoded_key).expect("Invalid key size for Hmac");

    let resource_uri = format!("{}%2Fdevices%2F{}", hostname, device_id);

    let expiry_timestamp = expiry.timestamp();

    let to_sign = format!("{}\n{}", resource_uri, expiry_timestamp);

    let token = generate_token(&decoded_key, &to_sign);

    let sas = format!(
        "SharedAccessSignature sr={}&{}&se={}",
        resource_uri, token, expiry_timestamp
    );

    sas
}

#[derive(Clone)]
pub(crate) struct AzureIotHub {
    pub client: Client,
    connection: Arc<Mutex<Connection>>,
    connection_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    stop_signal: Arc<AtomicBool>,
}

impl AzureIotHub {
    pub fn new(connection_string: String) -> AzureIotHub {
        let (hostname, device_id, shared_access_key) = parse_connection_string(connection_string);
        let mut mqttoptions = MqttOptions::new(&device_id, &hostname, 8883);
        mqttoptions
            .set_transport(Transport::tls_with_default_config())
            .set_keep_alive(Duration::from_secs(5))
            .set_credentials(
                generate_username(&hostname, &device_id),
                generate_shared_access_signature(
                    &hostname,
                    &device_id,
                    &shared_access_key,
                    &(Utc::now() + Duration::from_secs(600)),
                ),
            );
        let (client, connection) = Client::new(mqttoptions, 10);

        AzureIotHub {
            client,
            connection: Arc::new(Mutex::new(connection)),
            connection_thread: Arc::new(Mutex::new(None)),
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn send_telemetry(&mut self, payload: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.client.publish(
            "devices/symmetric-buoy-han/messages/events/",
            QoS::AtLeastOnce,
            false,
            payload.as_bytes(),
        )?;
        thread::sleep(Duration::from_millis(1000));
        Ok(())
    }

    pub fn is_started(&self) -> bool {
        self.connection_thread.lock().unwrap().is_some()
    }

    pub fn start(&mut self) -> Result<(), &'static str> {
        if self.is_started() {
            return Err("Failed to connection: the connection has already be established");
        }
        let connection_clone = self.connection.clone();
        let stop_signal_clone = self.stop_signal.clone();
        let connection_thread = thread::spawn(move || {
            for (i, notification) in connection_clone.lock().unwrap().iter().enumerate() {
                match notification {
                    Ok(notif) => {
                        debug!("{i}. Notification = {notif:?}");
                    }
                    Err(error) => {
                        debug!("{i}. Notification = {error:?}");
                        return;
                    }
                }
                if stop_signal_clone
                    .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        });
        self.connection_thread = Arc::new(Mutex::new(Some(connection_thread)));
        info!("IotHub Service Started");
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), &'static str> {
        if !self.is_started() {
            return Err("");
        }
        self.stop_signal.store(true, Ordering::Relaxed);
        self.connection_thread
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        info!("IotHub Service Stopped");
        Ok(())
    }
}
