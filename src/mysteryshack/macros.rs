macro_rules! json {
    {$($keys:expr => $values:expr),*} => ({
        let kv_pairs = vec![ $(($keys.to_string(), json!($values))),* ];
        ::rustc_serialize::json::Json::Object(kv_pairs.into_iter().collect())
    });
    ($value:expr) => ({
        use ::rustc_serialize::json::ToJson;
        $value.to_json()
    });
    [[ $($values:expr),* ]] => (::rustc_serialize::json::Json::Array(vec![ $(json!($values)),* ]));
}
