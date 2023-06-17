use cyfs_base::{BuckyError, BuckyErrorCode};
use sfo_sql::ErrorMap;

#[cfg(feature = "stack")]
pub mod shared_object_stack_ex;

pub mod json_object;
pub mod error_util;
pub mod http_util;


#[derive(Clone)]
pub struct SqlErrorToBuckyError;

impl ErrorMap for SqlErrorToBuckyError {
    type OutError = BuckyError;
    type InError = sfo_sql::SqlError;

    fn map(e: sfo_sql::SqlError, msg: &str) -> BuckyError {
        match e {
            sfo_sql::SqlError::RowNotFound => {
                // let msg = format!("not found, {}", msg);
                BuckyError::new(BuckyErrorCode::NotFound, "not found")
            },
            sfo_sql::SqlError::Database(ref err) => {
                let msg = format!("sql error: {:?} info:{}", e, msg);
                if cfg!(test) {
                    println!("{}", msg);
                } else {
                    log::error!("SqlErrorToBuckyError:{}", msg);
                }

                if let Some(code) = err.code() {
                    if code.to_string().as_str() == "23000" {
                        return BuckyError::new(BuckyErrorCode::AlreadyExists, "already exists");
                    }
                }
                BuckyError::new(BuckyErrorCode::SqliteError, msg)
            }
            _ => {
                let msg = format!("sql error: {:?} info:{}", e, msg);
                if cfg!(test) {
                    println!("{}", msg);
                } else {
                    log::error!("SqlErrorToBuckyError:{}", msg);
                }
                BuckyError::new(BuckyErrorCode::SqliteError, "")
            }
        }
    }
}
