use cyfs_base::{BuckyError, BuckyErrorCode};
use sfo_http::errors::ErrorCode;

#[macro_export]
macro_rules! app_err {
    ( $err: expr, $($arg:tt)*) => {
        {
            log::error!("{} {}", stringify!($err), format!($($arg)*));
            cyfs_base::BuckyError::new(cyfs_base::BuckyErrorCodeEx::DecError($err), format!("app_code_err:{} msg:{}", stringify!($err), format!($($arg)*)))
        }
    };
}

#[macro_export]
macro_rules! cyfs_err {
    ( $err: expr, $($arg:tt)*) => {
        {
            log::error!("{}", format!($($arg)*));
            cyfs_base::BuckyError::new($err, format!("msg:{}", format!($($arg)*)))
        }
    };
}

#[macro_export]
macro_rules! into_cyfs_err {
    ($err: expr, $($arg:tt)*) => {
        |e| {
            log::error!("{} err:{:?}", format!($($arg)*), e);
            cyfs_base::BuckyError::new($err, format!("{} err {}", format!($($arg)*), e))
        }
    }
}

#[macro_export]
macro_rules! into_app_err {
    ($err: expr, $($arg:tt)*) => {
        |e| {
            log::error!("{} {} err:{:?}", stringify!($err), format!($($arg)*), e);
            cyfs_base::BuckyError::new(cyfs_base::BuckyErrorCodeEx::DecError($err), format!("app_code_err:{} {} err {}", stringify!($err), format!($($arg)*), e))
        }
    }
}

#[macro_export]
macro_rules! into_bucky_err {
    ($($arg:tt)*) => {
        |e| {
            log::error!("{} err:{:?}", format!($($arg)*), e);
            e.into_bucky_error(format!($($arg)*))
        }
    }
}

pub trait IntoBuckyError {
    fn into_bucky_error(self, msg: impl Into<String>) -> BuckyError;
}

impl IntoBuckyError for sfo_http::errors::Error {
    fn into_bucky_error(self, msg: impl Into<String>) -> BuckyError {
        match self.code() {
            ErrorCode::Failed => {
                BuckyError::new(BuckyErrorCode::Failed, format!("{} {}", msg.into(), self.msg()))
            }
            ErrorCode::InvalidData => {
                BuckyError::new(BuckyErrorCode::InvalidData, format!("{} {}", msg.into(), self.msg()))
            }
            ErrorCode::ConnectFailed => {
                BuckyError::new(BuckyErrorCode::ConnectFailed, format!("{} {}", msg.into(), self.msg()))
            }
            ErrorCode::InvalidParam => {
                BuckyError::new(BuckyErrorCode::InvalidParam, format!("{} {}", msg.into(), self.msg()))
            }
        }
    }
}

impl IntoBuckyError for sfo_http::token_helper::errors::Error {
    fn into_bucky_error(self, msg: impl Into<String>) -> BuckyError {
        if self.kind() == &sfo_http::token_helper::errors::ErrorKind::ExpiredSignature {
            BuckyError::new(BuckyErrorCode::Expired, format!("{} {}", msg.into(), self))
        } else {
            BuckyError::new(BuckyErrorCode::Failed, format!("{} {}", msg.into(), self))
        }
    }
}

impl IntoBuckyError for serde_json::Error {
    fn into_bucky_error(self, msg: impl Into<String>) -> BuckyError {
        BuckyError::new(BuckyErrorCode::Failed, format!("{} {}", msg.into(), self))
    }
}

impl IntoBuckyError for tide::Error {
    fn into_bucky_error(self, msg: impl Into<String>) -> BuckyError {
        BuckyError::new(BuckyErrorCode::Failed, format!("{} {}", msg.into(), self))
    }
}

impl IntoBuckyError for std::io::Error {
    fn into_bucky_error(self, msg: impl Into<String>) -> BuckyError {
        BuckyError::new(BuckyErrorCode::Failed, format!("{} {}", msg.into(), self))
    }
}

pub fn get_app_err_code(ret: &BuckyError) -> u16 {
    if let BuckyErrorCode::DecError(code) = ret.code() {
        code
    } else {
        u16::MAX
    }
}
