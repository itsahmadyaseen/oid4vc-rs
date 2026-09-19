use ciborium::Value;
use std::collections::BTreeMap;

fn main() {
    let mut map = BTreeMap::new();
    map.insert(
        Value::Text("digestID".to_string()),
        Value::Integer(1.into()),
    );
    map.insert(
        Value::Text("random".to_string()),
        Value::Bytes(vec![0; 32]),
    );
    map.insert(
        Value::Text("elementIdentifier".to_string()),
        Value::Text("family_name".to_string()),
    );
    // element.value is CBOR bytes, we parse it
    let element_value: Value = ciborium::from_reader(b"\"Doe\"".as_slice()).unwrap();
    map.insert(
        Value::Text("elementValue".to_string()),
        element_value,
    );
    
    let item = Value::Map(map);
    let mut item_bytes = Vec::new();
    ciborium::into_writer(&item, &mut item_bytes).unwrap();
    println!("{:?}", item_bytes);
}
