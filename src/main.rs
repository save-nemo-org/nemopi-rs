mod communication;

use crate::communication::AzureIotHub;
use std::thread;
use std::time::Duration;

fn main() {
    env_logger::init();

    let connection_string = std::env::var("CONNECTION_STRING")
        .expect("Set IoT Hub connection string in the CONNECTION_STRING environment variable");

    let mut iothub = AzureIotHub::new(connection_string);

    iothub.start().unwrap();
    thread::sleep(Duration::from_secs(1));

    let mut iothub_clone = iothub.clone();
    thread::spawn(move || {
        iothub_clone.get_device_twin().unwrap();
        thread::sleep(Duration::from_millis(1000));
        iothub_clone.send_telemetry("foo").unwrap();
        thread::sleep(Duration::from_millis(1000));
    });

    thread::sleep(Duration::from_secs(200));
    iothub.stop().unwrap();
}
