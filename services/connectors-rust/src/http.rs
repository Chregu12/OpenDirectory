use reqwest::{blocking::Client, header, redirect::Policy, StatusCode};
use std::{
    io::Read,
    time::{Duration, SystemTime},
};
use url::Url;

pub const MAX_BODY: u64 = 262_144;

#[derive(Debug)]
pub struct Error {
    pub code: String,
    pub retry_after: Option<u64>,
}
impl Error {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.into(),
            retry_after: None,
        }
    }
}

pub fn bearer(token: &str) -> bool {
    !token.trim_end_matches('=').is_empty()
        && token.len() <= 16_384
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._~+/-=".contains(&c))
        && !token.trim_end_matches('=').contains('=')
}

fn retry_after(value: Option<&header::HeaderValue>) -> u64 {
    value
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.parse::<u64>().ok().filter(|n| *n > 0).or_else(|| {
                httpdate::parse_http_date(s)
                    .ok()
                    .and_then(|date| date.duration_since(SystemTime::now()).ok())
                    .map(|d| d.as_secs().saturating_add(1))
                    .filter(|n| *n > 0)
            })
        })
        .unwrap_or(60)
        .min(3600)
}

pub fn client(stage: &str, headers: header::HeaderMap) -> Result<Client, Error> {
    let client = Client::builder()
        .redirect(Policy::none())
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| Error::new(&format!("{stage}_unavailable")))?;
    Ok(client)
}

pub fn read_json(
    client: &Client,
    url: &Url,
    token: &str,
    stage: &str,
) -> Result<serde_json::Value, Error> {
    request_json(client.get(url.clone()).bearer_auth(token), stage)
}

pub fn request_json(
    request: reqwest::blocking::RequestBuilder,
    stage: &str,
) -> Result<serde_json::Value, Error> {
    request_json_with_headers(request, stage).map(|(body, _)| body)
}

pub fn request_json_with_headers(
    request: reqwest::blocking::RequestBuilder,
    stage: &str,
) -> Result<(serde_json::Value, header::HeaderMap), Error> {
    let response = request
        .send()
        .map_err(|_| Error::new(&format!("{stage}_unavailable")))?;
    let status = response.status();
    if status != StatusCode::OK {
        let mut error = Error::new(&format!("{stage}_http_{}", status.as_u16()));
        if status == StatusCode::TOO_MANY_REQUESTS {
            error.retry_after = Some(retry_after(response.headers().get(header::RETRY_AFTER)));
        }
        if stage == "github_copilot"
            && [StatusCode::FORBIDDEN, StatusCode::TOO_MANY_REQUESTS].contains(&status)
        {
            let headers = response.headers();
            if headers.contains_key(header::RETRY_AFTER) {
                error.retry_after = Some(retry_after(headers.get(header::RETRY_AFTER)));
            } else if headers
                .get("x-ratelimit-remaining")
                .is_some_and(|v| v == "0")
            {
                let reset = headers
                    .get("x-ratelimit-reset")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                error.retry_after = Some(
                    reset
                        .map(|v| v.saturating_sub(now).clamp(1, 3600))
                        .unwrap_or(60),
                );
            }
        }
        return Err(error);
    }
    if !response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.contains("application/json")
                || stage == "slack_directory"
                    && v.split(';').next().is_some_and(|media| {
                        media.trim().eq_ignore_ascii_case("application/scim+json")
                    })
        })
    {
        return Err(Error::new(&format!("{stage}_unavailable")));
    }
    let headers = response.headers().clone();
    let mut bytes = Vec::new();
    response
        .take(MAX_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new(&format!("{stage}_unavailable")))?;
    if bytes.len() as u64 > MAX_BODY {
        return Err(Error::new(&format!("{stage}_unavailable")));
    }
    let raw = serde_json::from_slice(&bytes)
        .map_err(|_| Error::new(&format!("{stage}_invalid_response")))?;
    Ok((raw, headers))
}

pub fn text(value: &str, limit: usize) -> bool {
    !value.trim().is_empty()
        && value.encode_utf16().count() <= limit
        && !value.chars().any(char::is_control)
}

pub fn email(value: &str) -> bool {
    let parts: Vec<_> = value.split('@').collect();
    text(value, 254)
        && parts.len() == 2
        && parts.iter().all(|part| !part.is_empty())
        && !value.chars().any(char::is_whitespace)
}
