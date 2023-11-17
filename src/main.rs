use std::thread;
use std::time::Duration;

use rumqttc::QoS;

mod communication;

use crate::communication::AzureIotHub;

fn main() {
    let connection_string = std::env::var("CONNECTION_STRING")
        .expect("Set IoT Hub connection string in the CONNECTION_STRING environment variable");

    let mut iothub = AzureIotHub::new(connection_string);

    {
        iothub.start().unwrap();

        let mut c: rumqttc::Client = iothub.client.clone();

        // client.subscribe("hello/rumqtt", QoS::AtMostOnce).unwrap();
        thread::spawn(move || loop {
            c.publish(
                "devices/symmetric-buoy-han/messages/events/",
                QoS::AtLeastOnce,
                false,
                "foo".as_bytes(),
            )
            .unwrap();
            thread::sleep(Duration::from_millis(1000));
        });

        thread::sleep(Duration::from_secs(10));
        iothub.stop().unwrap();
    }
}
