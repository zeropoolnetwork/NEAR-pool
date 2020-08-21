pub use kvdb_web::Database as KvdbDatabase;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Database {
    pub(crate) inner: KvdbDatabase,
}

#[wasm_bindgen]
impl Database {
    pub async fn open(name: String, columns: u32) -> Result<Database, JsValue> {
        let inner = KvdbDatabase::open(name, columns)
            .await
            .map_err(|err| format!("{}", err))?;
        Ok(Database { inner })
    }
}
