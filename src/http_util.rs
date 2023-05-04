#![allow(unused)]

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use cyfs_base::*;
use http_client::http_types;
use rustls::{Certificate, RootCertStore, ServerCertVerified, ServerCertVerifier};
use tide::convert::{Deserialize, Serialize};
use surf::http::{Method, Mime};
use surf::{Request, Url};
use surf::http::headers::CONTENT_TYPE;
use tide::{Response, StatusCode};
use crate::into_bucky_err;
use crate::error_util::IntoBuckyError;

pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(&self,
                          _roots: &RootCertStore,
                          _presented_certs: &[Certificate],
                          _dns_name: webpki::DNSNameRef,
                          _ocsp_response: &[u8]) -> Result<ServerCertVerified, rustls::TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

fn make_config() -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::new();
    config.dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    Arc::new(config)
}

fn create_http_client(max_connections: Option<usize>, skip_tls: bool) -> http_client::h1::H1Client {
    use http_client::HttpClient;
    let mut config = http_client::Config::new()
        .set_timeout(Some(Duration::from_secs(30)))
        .set_max_connections_per_host(max_connections.unwrap_or(50))
        .set_http_keep_alive(true);
    if skip_tls {
        config = config.set_tls_config(Some(make_config()));
    }
    let mut client = http_client::h1::H1Client::new();
    client.set_config(config);
    client
}

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

pub async fn http_get_request3(url: &str) -> BuckyResult<surf::Response> {
    sfo_http::http_util::http_get_request3(url).await.map_err(into_bucky_err!("request url {} failed", url))
}

pub async fn http_request(req: http_types::Request) -> BuckyResult<surf::Response> {
    sfo_http::http_util::http_request(req).await.map_err(into_bucky_err!("request failed"))
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
    pub fn new(max_connections: usize, base_url: Option<&str>) -> BuckyResult<Self> {
        Ok(Self {
            client: sfo_http::http_util::HttpClient::new(max_connections, base_url).map_err(into_bucky_err!())?,
        })
    }

    pub fn new_with_no_cert_verify(max_connections: usize, base_url: Option<&str>) -> BuckyResult<Self> {
        Ok(Self {
            client: sfo_http::http_util::HttpClient::new_with_no_cert_verify(max_connections, base_url).map_err(into_bucky_err!())?,
        })
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
