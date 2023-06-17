#![allow(unused)]

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use cyfs_base::*;
pub use sfo_http::http_util::header::{HeaderName, HeaderValue};
use sfo_http::http_util::JsonValue;
use tide::convert::{Deserialize, Serialize};
use tide::{Response, StatusCode};
use crate::into_bucky_err;
use crate::error_util::IntoBuckyError;

pub async fn http_post_request(url: &str, param: Vec<u8>, content_type: Option<&str>) -> BuckyResult<(Vec<u8>, Option<String>)> {
    sfo_http::http_util::http_post_request(url, param, content_type).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_post_request2<T: for<'de> Deserialize<'de>>(url: &str, param: Vec<u8>, content_type: Option<&str>) -> BuckyResult<T> {
    sfo_http::http_util::http_post_request2(url, param, content_type).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_post_request3<T: for<'de> Deserialize<'de>, P: Serialize>(url: &str, param: &P) -> BuckyResult<T> {
    sfo_http::http_util::http_post_request3(url, param).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_get_request2<T: for<'de> Deserialize<'de>>(url: &str) -> BuckyResult<T> {
    sfo_http::http_util::http_get_request2(url).await.map_err(into_bucky_err!("request url {} failed", url))
}


pub async fn http_get_request(url: &str) -> BuckyResult<(Vec<u8>, Option<String>)> {
    sfo_http::http_util::http_get_request(url).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_get_request3(url: &str) -> BuckyResult<sfo_http::http_util::Response> {
    sfo_http::http_util::http_get_request3(url).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_request(req: sfo_http::http_util::Request) -> BuckyResult<sfo_http::http_util::Response> {
    sfo_http::http_util::http_request(req).await.map_err(into_bucky_err!("request failed"))
}

pub async fn http_post_json(url: &str, param: JsonValue) -> BuckyResult<JsonValue> {
    sfo_http::http_util::http_post_json(url, param).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_post_json2<T: for<'de> Deserialize<'de>>(url: &str, param: JsonValue) -> BuckyResult<T> {
    sfo_http::http_util::http_post_json2(url, param).await.map_err(into_bucky_err!("request url {} failed", url))
}
#[derive(Clone)]
pub struct HttpClient {
    client: sfo_http::http_util::HttpClient,
}

impl Debug for HttpClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HttpClient")
    }
}

impl HttpClient {
    pub fn new(max_connections: usize, base_url: Option<&str>) -> Self {
        Self {
            client: sfo_http::http_util::HttpClient::new(max_connections, base_url),
        }
    }

    pub fn new_with_no_cert_verify(max_connections: usize, base_url: Option<&str>) -> Self {
        Self {
            client: sfo_http::http_util::HttpClient::new_with_no_cert_verify(max_connections, base_url),
        }
    }

    pub async fn get_json<T: for<'de> Deserialize<'de>>(&self, uri: &str) -> BuckyResult<T> {
        self.client.get_json(uri).await.map_err(into_bucky_err!())
    }

    pub async fn get(&self, uri: &str) -> BuckyResult<(Vec<u8>, Option<String>)> {
        self.client.get(uri).await.map_err(into_bucky_err!())
    }

    pub async fn post_json<T: for<'de> Deserialize<'de>, P: Serialize>(&self, uri: &str, param: &P) -> BuckyResult<T> {
        self.client.post_json(uri, param).await.map_err(into_bucky_err!())
    }

    pub async fn post(&self, uri: &str, param: Vec<u8>, content_type: Option<&str>) -> BuckyResult<(Vec<u8>, Option<String>)> {
        self.client.post(uri, param, content_type).await.map_err(into_bucky_err!())
    }
}

#[derive(Default)]
pub struct HttpClientBuilder {
    builder: sfo_http::http_util::HttpClientBuilder
}

impl HttpClientBuilder {
    pub fn set_base_url(mut self, base_url: &str) -> Self {
        self.builder = self.builder.set_base_url(base_url);
        self
    }
    pub fn add_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> BuckyResult<Self> {
        self.builder = self.builder.add_header(name, value).map_err(into_bucky_err!())?;
        Ok(self)
    }

    pub fn set_http_keep_alive(mut self, keep_alive: bool) -> Self {
        self.builder = self.builder.set_http_keep_alive(keep_alive);
        self
    }

    pub fn set_tcp_no_delay(mut self, no_delay: bool) -> Self {
        self.builder = self.builder.set_tcp_no_delay(no_delay);
        self
    }

    pub fn set_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.builder = self.builder.set_timeout(timeout);
        self
    }

    pub fn set_max_connections_per_host(mut self, max_connections_per_host: usize) -> Self {
        self.builder = self.builder.set_max_connections_per_host(max_connections_per_host);
        self
    }

    pub fn set_verify_tls(mut self, verify_tls: bool) -> Self {
        self.builder = self.builder.set_verify_tls(verify_tls);
        self
    }

    pub fn build(self) -> HttpClient {
        HttpClient {
            client: self.builder.build(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct HttpJsonResult<T>
{
    pub err: u16,
    pub msg: String,
    pub result: Option<T>
}

impl <T> HttpJsonResult<T>
    where T: Serialize
{
    pub fn from(ret: BuckyResult<T>) -> Self {
        match ret {
            Ok(data) => {
                HttpJsonResult {
                    err: 0,
                    msg: "".to_string(),
                    result: Some(data)
                }
            },
            Err(err) => {
                HttpJsonResult {
                    err: err.code().into(),
                    msg: format!("{}", err),
                    result: None
                }
            }
        }
    }

    pub fn to_response(&self) -> Response {
        let mut resp = Response::new(StatusCode::Ok);
        resp.set_content_type("application/json");
        resp.set_body(serde_json::to_string(self).unwrap());
        resp
    }
}
