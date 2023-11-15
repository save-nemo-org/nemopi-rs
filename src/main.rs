use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rumqttc::{Client, MqttOptions, QoS, Transport};
use sha2::Sha256;
use std::thread;
use std::time::Duration;

fn parse_connection_string(connection_string: String) -> (String, String, String) {
    let mut hostname = None;
    let mut key = None;
    let mut device_id = None;

    let parts: Vec<&str> = connection_string.split(';').collect();
    for p in parts {
        if p.starts_with("HostName=") {
            hostname = p.strip_prefix("HostName=");
        } else if p.starts_with("DeviceId=") {
            device_id = p.strip_prefix("DeviceId=")
        } else if p.starts_with("SharedAccessKey=") {
            key = p.strip_prefix("SharedAccessKey=")
        }
    }

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

fn main() {
    let connection_string = std::env::var("CONNECTION_STRING")
        .expect("Set IoT Hub connection string in the CONNECTION_STRING environment variable");
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

    let (mut client, mut connection) = Client::new(mqttoptions, 10);

    // client.subscribe("hello/rumqtt", QoS::AtMostOnce).unwrap();
    thread::spawn(move || {
        client
            .publish(
                "devices/symmetric-buoy-han/messages/events/",
                QoS::AtLeastOnce,
                false,
                "foo".as_bytes(),
            )
            .unwrap();
        thread::sleep(Duration::from_millis(1000));
    });

    // Iterate to poll the eventloop for connection progress
    for (i, notification) in connection.iter().enumerate() {
        match notification {
            Ok(event) => println!("Pkt {}: Event = {:?}", i, event),
            Err(err) => {
                println!("Pkt {}: Error = {:?}", i, err);
                thread::sleep(Duration::from_millis(1000));
            }
        };
    }
}
