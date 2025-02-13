use std::fmt;

use anyhow::Result;
use chrono::{Duration, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::get_content;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    aud: String,
    exp: i64,
}

const SECRET_KEY: &str = "./fixtures/chacha20.key";
const AUDIENCE: &[&str] = &["tencent", "alibaba", "netease"];

pub fn process_jwt_sign(sub: String, aud: String, exp: String) -> Result<String> {
    let re = Regex::new(r"(?P<value>\d+)(?P<unit>[dhms])")?;
    let mut duration: TimeDelta = Duration::days(14);
    for cap in re.captures_iter(&exp) {
        let (value, unit) = (cap["value"].parse::<i64>()?, &cap["unit"]);
        duration = match unit {
            "d" => Duration::days(value),
            "h" => Duration::hours(value),
            "m" => Duration::minutes(value),
            "s" => Duration::seconds(value),
            _ => Duration::days(value),
        };
    }

    let expiration_time = Utc::now()
        .checked_add_signed(duration)
        .expect("invalid timestamp")
        .timestamp();

    let claims = Claims {
        sub,
        aud,
        exp: expiration_time,
    };

    let secret = get_content(SECRET_KEY)?;

    let header = Header {
        alg: Algorithm::HS256,
        ..Default::default()
    };

    let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&secret))?;

    Ok(token)
}

pub fn process_jwt_verify(token: &str) -> Result<Claims> {
    let secret = get_content(SECRET_KEY)?;

    let mut validation = Validation::new(Algorithm::HS256);
    // !important 设置aud才能正常校验
    validation.set_audience(AUDIENCE);
    jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(&secret), &validation)
        .map(|data| data.claims)
        .map_err(|err| anyhow::anyhow!(err))
}

impl fmt::Display for Claims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Claims(sub={}, aud={}, exp={})",
            self.sub, self.aud, self.exp
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_verify() {
        let token = process_jwt_sign(
            "mariana".to_string(),
            "tencent".to_string(),
            "14d".to_string(),
        )
        .unwrap();
        let claims = process_jwt_verify(&token);
        assert!(claims.is_ok());
    }
}
