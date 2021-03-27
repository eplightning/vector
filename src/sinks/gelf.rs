use crate::config::LogSchema;
use crate::event::LogEvent;
use crate::sinks::util::encoding::EncodingConfigWithDefault;
use crate::{
    config::{DataType, GenerateConfig, SinkConfig, SinkContext, SinkDescription},
    event::Event,
    http::{Auth, HttpClient, MaybeAuth},
    sinks::util::{
        buffer::compression::GZIP_DEFAULT,
        encoding::EncodingConfiguration,
        http::{BatchedHttpSink, HttpSink, RequestConfig},
        BatchConfig, BatchSettings, Buffer, Compression, Concurrency, TowerRequestConfig, UriSerde,
    },
    tls::{TlsOptions, TlsSettings},
    Value,
};
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use futures::{future, FutureExt, SinkExt};
use http::{
    header::{self, HeaderName, HeaderValue},
    Method, Request, StatusCode, Uri,
};
use hyper::Body;
use indexmap::IndexMap;
use lazy_static::lazy_static;
use regex::Regex;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::io::Write;

#[derive(Deserialize, Serialize, Debug, Clone)]
// TODO: add back when serde-rs/serde#1358 is addressed
// #[serde(deny_unknown_fields)]
pub struct GelfSinkConfig {
    #[serde(flatten)]
    pub mode: Mode,
    #[serde(
        skip_serializing_if = "crate::serde::skip_serializing_if_default",
        default
    )]
    pub encoding: EncodingConfigWithDefault<Encoding>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Derivative)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Mode {
    Http(GelfHttpSinkConfig),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct GelfHttpSinkConfig {
    pub uri: UriSerde,
    pub auth: Option<Auth>,
    #[serde(default)]
    pub compression: Compression,
    #[serde(default)]
    pub batch: BatchConfig,
    #[serde(default)]
    pub request: RequestConfig,
    pub tls: Option<TlsOptions>,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Derivative)]
#[serde(rename_all = "snake_case")]
#[derivative(Default)]
pub enum Encoding {
    #[derivative(Default)]
    Default,
}

enum GelfAdditionalField {
    String(String),
    Integer(i64),
    Float(f64),
}

impl From<f64> for GelfAdditionalField {
    fn from(value: f64) -> Self {
        GelfAdditionalField::Float(value)
    }
}

impl From<i64> for GelfAdditionalField {
    fn from(value: i64) -> Self {
        GelfAdditionalField::Integer(value)
    }
}

impl From<String> for GelfAdditionalField {
    fn from(value: String) -> Self {
        GelfAdditionalField::String(value)
    }
}

struct GelfMessage<'a> {
    version: &'a str,
    host: String,
    short_message: String,
    full_message: Option<String>,
    level: Option<u8>,
    timestamp: Option<DateTime<Utc>>,
    additional: HashMap<String, GelfAdditionalField>,
}

#[derive(Debug, Snafu)]
enum BuildError {
    #[snafu(display("{}: {}", source, name))]
    InvalidHeaderName {
        name: String,
        source: header::InvalidHeaderName,
    },
    #[snafu(display("{}: {}", source, value))]
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
}

enum GelfConvertError {
    MissingHost,
    MissingShortMessage,
    EmptyHost,
    EmptyShortMessage,
}

fn event_to_gelf(
    event: &'_ mut LogEvent,
    schema: &'_ LogSchema,
) -> Result<GelfMessage<'static>, GelfConvertError> {
    let short_message = event
        .remove(schema.message_key())
        .ok_or(GelfConvertError::MissingShortMessage)?
        .to_string_lossy();
    let host = event
        .remove(schema.host_key())
        .ok_or(GelfConvertError::MissingHost)?
        .to_string_lossy();

    if short_message.is_empty() {
        return Err(GelfConvertError::EmptyShortMessage);
    }
    if host.is_empty() {
        return Err(GelfConvertError::EmptyHost);
    }

    let mut message = GelfMessage {
        version: "1.1",
        short_message,
        host,
        full_message: None,
        level: None,
        timestamp: None,
        additional: HashMap::new(),
    };

    message.timestamp = Some(match event.remove(schema.timestamp_key()) {
        Some(Value::Timestamp(ts)) => ts,
        _ => chrono::Utc::now(),
    });

    for (k, v) in event.all_fields() {
        match v {
            Value::Float(float) => {
                message
                    .additional
                    .insert(k, GelfAdditionalField::from(*float));
            }
            Value::Integer(int) => {
                message
                    .additional
                    .insert(k, GelfAdditionalField::from(*int));
            }
            _ => {
                message
                    .additional
                    .insert(k, GelfAdditionalField::from(v.to_string_lossy()));
            }
        }
    }

    // TODO: optional full_message, level

    Ok(message)
}

impl<'a> Serialize for GelfMessage<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_key("version")?;
        map.serialize_value(self.version)?;

        map.serialize_key("host")?;
        map.serialize_value(&self.host)?;

        map.serialize_key("short_message")?;
        map.serialize_value(&self.short_message)?;

        match &self.timestamp {
            Some(ts) => {
                let gelf_timestamp = ts.timestamp_millis() as f64 / 1000.0;

                map.serialize_key("timestamp")?;
                map.serialize_value(&gelf_timestamp)?;
            }
            None => (),
        }

        match &self.full_message {
            Some(full_message) => {
                map.serialize_key("full_message")?;
                map.serialize_value(full_message)?;
            }
            None => (),
        }

        match self.level {
            Some(level) => {
                map.serialize_key("level")?;
                map.serialize_value(&level)?;
            }
            None => (),
        }

        for (k, v) in self.additional.iter() {
            let sanitized = INVALID_CHARS_REGEX.replace_all(&k, "_");
            let field_key = ["_", &sanitized].concat();

            map.serialize_key(&field_key)?;

            match v {
                GelfAdditionalField::Integer(int) => map.serialize_value(int)?,
                GelfAdditionalField::Float(float) => map.serialize_value(float)?,
                GelfAdditionalField::String(str) => map.serialize_value(str)?,
            }
        }

        map.end()
    }
}

lazy_static! {
    static ref REQUEST_DEFAULTS: TowerRequestConfig = TowerRequestConfig {
        concurrency: Concurrency::Fixed(10),
        timeout_secs: Some(30),
        rate_limit_num: Some(u64::max_value()),
        ..Default::default()
    };
    static ref INVALID_CHARS_REGEX: Regex = Regex::new("[^\\w\\.\\-]").unwrap();
}

inventory::submit! {
    SinkDescription::new::<GelfSinkConfig>("gelf")
}

impl GenerateConfig for GelfSinkConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(
            r#"uri = "https://10.22.212.22:9000/endpoint"
            mode = "http""#,
        )
        .unwrap()
    }
}

struct GelfHttpSink {
    config: GelfHttpSinkConfig,
    encoding: EncodingConfigWithDefault<Encoding>,
}

impl GelfHttpSinkConfig {
    fn build(
        &self,
        cx: SinkContext,
        encoding: &EncodingConfigWithDefault<Encoding>,
    ) -> crate::Result<(super::VectorSink, super::Healthcheck)> {
        let tls = TlsSettings::from_options(&self.tls)?;
        let client = HttpClient::new(tls)?;

        let healthcheck = match cx.healthcheck.uri.clone() {
            Some(healthcheck_uri) => {
                healthcheck(healthcheck_uri, self.auth.clone(), client.clone()).boxed()
            }
            None => future::ok(()).boxed(),
        };

        let http_sink = GelfHttpSink {
            config: GelfHttpSinkConfig {
                auth: self.auth.choose_one(&self.uri.auth)?,
                uri: self.uri.with_default_parts(),
                ..self.clone()
            },
            encoding: encoding.clone(),
        };

        validate_headers(&http_sink.config.request.headers, &http_sink.config.auth)?;

        let batch = BatchSettings::default()
            .bytes(bytesize::mib(10u64))
            .timeout(1)
            .parse_config(http_sink.config.batch)?;
        let request = http_sink
            .config
            .request
            .tower
            .unwrap_with(&REQUEST_DEFAULTS);

        let sink = BatchedHttpSink::new(
            http_sink,
            Buffer::new(batch.size, Compression::None),
            request,
            batch.timeout,
            client,
            cx.acker(),
        )
        .sink_map_err(|error| error!(message = "Fatal HTTP sink error.", %error));

        let sink = super::VectorSink::Sink(Box::new(sink));

        Ok((sink, healthcheck))
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "gelf")]
impl SinkConfig for GelfSinkConfig {
    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(super::VectorSink, super::Healthcheck)> {
        match &self.mode {
            Mode::Http(config) => config.build(cx, &self.encoding),
        }
    }

    fn input_type(&self) -> DataType {
        DataType::Log
    }

    fn sink_type(&self) -> &'static str {
        "gelf"
    }
}

#[async_trait::async_trait]
impl HttpSink for GelfHttpSink {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn encode_event(&self, mut event: Event) -> Option<Self::Input> {
        self.encoding.apply_rules(&mut event);
        let mut event = event.into_log();

        let message = event_to_gelf(&mut event, crate::config::log_schema()).ok()?;
        let body = serde_json::to_vec(&message).ok()?;

        Some(body)
    }

    async fn build_request(&self, mut body: Self::Output) -> crate::Result<http::Request<Vec<u8>>> {
        let uri: Uri = self.config.uri.uri.clone();

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json");

        match self.config.compression {
            Compression::Gzip(level) => {
                builder = builder.header("Content-Encoding", "gzip");

                let level = level.unwrap_or(GZIP_DEFAULT) as u32;
                let mut w = GzEncoder::new(Vec::new(), flate2::Compression::new(level));
                w.write_all(&body).expect("Writing to Vec can't fail");
                body = w.finish().expect("Writing to Vec can't fail");
            }
            Compression::None => {}
        }

        for (header, value) in self.config.request.headers.iter() {
            builder = builder.header(header.as_str(), value.as_str());
        }

        let mut request = builder.body(body).unwrap();

        if let Some(auth) = &self.config.auth {
            auth.apply(&mut request);
        }

        Ok(request)
    }
}

async fn healthcheck(uri: UriSerde, auth: Option<Auth>, client: HttpClient) -> crate::Result<()> {
    let auth = auth.choose_one(&uri.auth)?;
    let uri = uri.with_default_parts();
    let mut request = Request::head(&uri.uri).body(Body::empty()).unwrap();

    if let Some(auth) = auth {
        auth.apply(&mut request);
    }

    let response = client.send(request).await?;

    match response.status() {
        StatusCode::OK => Ok(()),
        status => Err(super::HealthcheckError::UnexpectedStatus { status }.into()),
    }
}

fn validate_headers(map: &IndexMap<String, String>, auth: &Option<Auth>) -> crate::Result<()> {
    for (name, value) in map {
        if auth.is_some() && name.eq_ignore_ascii_case("Authorization") {
            return Err("Authorization header can not be used with defined auth options".into());
        }

        HeaderName::from_bytes(name.as_bytes()).with_context(|| InvalidHeaderName { name })?;
        HeaderValue::from_bytes(value.as_bytes()).with_context(|| InvalidHeaderValue { value })?;
    }

    Ok(())
}
