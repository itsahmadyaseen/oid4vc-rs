use ciborium::Value;
use std::collections::BTreeMap;

fn main() {
    let mut map = BTreeMap::new();
    map.insert(
        Value::Text("digestID".to_string()),
        Value::Integer(1.into()),
    );
    let mut item_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut item_bytes).unwrap();
    println!("{:?}", item_bytes);
}
