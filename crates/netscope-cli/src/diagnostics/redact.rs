use std::env;

// Redaction labels. Values are replaced, keys and structure are kept so the
// bundle still parses as the config/state it came from.
const HOME_LABEL: &str = "<home>";
const USER_LABEL: &str = "<user>";
const HOST_LABEL: &str = "<host>";
const SECRET_LABEL: &str = "[REDACTED]";
const TOKEN_LABEL: &str = "<redacted>";
const MAC_LABEL: &str = "[MAC]";
const IPV6_LABEL: &str = "<link-local>";

#[derive(Debug, Default)]
pub(crate) struct Redactor {
    pub(crate) homes: Vec<String>,
    pub(crate) users: Vec<String>,
    pub(crate) host: Option<String>,
    pub(crate) profiles: Vec<(String, String)>,
}

impl Redactor {
    pub(crate) fn detect(profile_names: &[String]) -> Self {
        let mut homes = Vec::new();
        let mut users = Vec::new();
        for key in ["SUDO_USER", "USER", "LOGNAME"] {
            if let Ok(user) = env::var(key) {
                if !user.is_empty() && !users.contains(&user) {
                    users.push(user);
                }
            }
        }
        if let Ok(home) = env::var("HOME") {
            if !home.is_empty() {
                homes.push(home);
            }
        }
        if users.iter().any(|user| user == "root") || env::var("HOME").as_deref() == Ok("/root") {
            homes.push("/root".to_string());
        }
        for user in users.iter().filter(|user| *user != "root") {
            homes.push(format!("/home/{user}"));
        }
        homes.sort_by_key(|home| std::cmp::Reverse(home.len()));
        homes.dedup();

        let host = hostname().filter(|host| host != "localhost");

        let mut profiles: Vec<(String, String)> = profile_names
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(index, name)| (name.to_string(), format!("<profile-{}>", index + 1)))
            .collect();
        profiles.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));

        Self {
            homes,
            users,
            host,
            profiles,
        }
    }

    /// `None` means the input looks binary; the caller leaves it untouched.
    pub(crate) fn redact(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.iter().take(8192).any(|byte| *byte == 0) {
            return None;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return None;
        };
        Some(self.redact_text(text).into_bytes())
    }

    pub(crate) fn redact_text(&self, text: &str) -> String {
        let mut text = text.to_string();
        // Home before username so /home/alice collapses to <home>, not /<user>.
        for home in &self.homes {
            text = replace_all(&text, home, HOME_LABEL);
        }
        for (name, label) in &self.profiles {
            text = replace_word(&text, name, label);
        }
        for user in &self.users {
            text = replace_word(&text, user, USER_LABEL);
        }
        if let Some(host) = &self.host {
            text = replace_word(&text, host, HOST_LABEL);
        }
        text = redact_assignments(&text);
        text = redact_jwts(&text);
        text = redact_macs(&text);
        text = redact_link_local_ipv6(&text);
        text = redact_runs(&text, 48, |byte| byte.is_ascii_hexdigit(), TOKEN_LABEL);
        text = redact_runs(&text, 40, |byte| byte.is_ascii_alphanumeric(), TOKEN_LABEL);
        text = redact_base64(&text);
        text
    }
}

fn hostname() -> Option<String> {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return None;
    }
    let raw = unsafe { std::ffi::CStr::from_ptr(name.nodename.as_ptr()) };
    let value = raw.to_string_lossy().into_owned();
    (!value.is_empty()).then_some(value)
}

fn replace_all(text: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    text.replace(needle, replacement)
}

fn word_boundary(byte: u8) -> bool {
    // `<` and `>` count as word characters so a later pass cannot rewrite an
    // already-emitted placeholder such as `<user>`.
    !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'<' || byte == b'>')
}

fn replace_word(text: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index + needle_bytes.len() <= bytes.len() {
        let matches = bytes[index..index + needle_bytes.len()] == *needle_bytes;
        let before_ok = index == 0 || word_boundary(bytes[index - 1]);
        let after = index + needle_bytes.len();
        let after_ok = after == bytes.len() || word_boundary(bytes[after]);
        if matches && before_ok && after_ok {
            out.push_str(&text[copied..index]);
            out.push_str(replacement);
            index = after;
            copied = after;
        } else {
            index += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

const SECRET_KEYS: [&str; 6] = [
    "authorization",
    "password",
    "api_key",
    "apikey",
    "secret",
    "token",
];

fn redact_assignments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        let Some(key) = SECRET_KEYS.iter().find(|key| {
            let len = key.len();
            index + len <= bytes.len()
                && bytes[index..index + len].eq_ignore_ascii_case(key.as_bytes())
                && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
        }) else {
            index += 1;
            continue;
        };
        let mut cursor = index + key.len();
        skip_spaces(bytes, &mut cursor);
        if bytes.get(cursor) == Some(&b'"') {
            cursor += 1;
            skip_spaces(bytes, &mut cursor);
        }
        if !matches!(bytes.get(cursor), Some(b'=') | Some(b':')) {
            index += key.len();
            continue;
        }
        cursor += 1;
        skip_spaces(bytes, &mut cursor);
        let quote = match bytes.get(cursor) {
            Some(b'"') => Some(b'"'),
            Some(b'\'') => Some(b'\''),
            _ => None,
        };
        let value_start = if quote.is_some() { cursor + 1 } else { cursor };
        let mut value_end = value_start;
        if *key == "authorization" && quote.is_none() {
            while value_end < bytes.len() && bytes[value_end] != b'\n' {
                value_end += 1;
            }
            while value_end > value_start && bytes[value_end - 1].is_ascii_whitespace() {
                value_end -= 1;
            }
        } else if let Some(quote) = quote {
            while value_end < bytes.len() && bytes[value_end] != quote && bytes[value_end] != b'\n'
            {
                value_end += 1;
            }
        } else {
            while value_end < bytes.len()
                && !bytes[value_end].is_ascii_whitespace()
                && !matches!(bytes[value_end], b',' | b'}' | b']' | b'"' | b'\'')
            {
                value_end += 1;
            }
        }
        if value_end > value_start {
            out.push_str(&text[copied..value_start]);
            out.push_str(SECRET_LABEL);
            copied = value_end;
        }
        index = value_end.max(cursor);
    }
    out.push_str(&text[copied..]);
    out
}

fn skip_spaces(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
}

fn base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn redact_jwts(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index + 3 <= bytes.len() {
        if &bytes[index..index + 3] != b"eyJ" || (index > 0 && !word_boundary(bytes[index - 1])) {
            index += 1;
            continue;
        }
        let mut cursor = index;
        let mut ok = true;
        for segment in 0..3 {
            let start = cursor;
            while cursor < bytes.len() && base64url(bytes[cursor]) {
                cursor += 1;
            }
            if cursor - start < 4 {
                ok = false;
                break;
            }
            if segment < 2 {
                if bytes.get(cursor) != Some(&b'.') {
                    ok = false;
                    break;
                }
                cursor += 1;
            }
        }
        if !ok {
            index += 1;
            continue;
        }
        out.push_str(&text[copied..index]);
        out.push_str(TOKEN_LABEL);
        copied = cursor;
        index = cursor;
    }
    out.push_str(&text[copied..]);
    out
}

fn hex_pair(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn redact_macs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index + 17 <= bytes.len() {
        let separator = match bytes[index + 2] {
            b':' => b':',
            b'-' => b'-',
            _ => {
                index += 1;
                continue;
            }
        };
        if index > 0 && hex_pair(bytes[index - 1]) {
            index += 1;
            continue;
        }
        let mut cursor = index;
        let mut valid = true;
        for group in 0..6 {
            if !hex_pair(bytes[cursor]) || !hex_pair(bytes[cursor + 1]) {
                valid = false;
                break;
            }
            cursor += 2;
            if group < 5 {
                if bytes.get(cursor) != Some(&separator) {
                    valid = false;
                    break;
                }
                cursor += 1;
            }
        }
        if !valid || bytes.get(cursor).is_some_and(|byte| hex_pair(*byte)) {
            index += 1;
            continue;
        }
        out.push_str(&text[copied..index]);
        out.push_str(MAC_LABEL);
        copied = cursor;
        index = cursor;
    }
    out.push_str(&text[copied..]);
    out
}

fn redact_link_local_ipv6(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index + 5 <= bytes.len() {
        let head = &bytes[index..index + 5];
        if !head.eq_ignore_ascii_case(b"fe80:")
            || (index > 0 && (hex_pair(bytes[index - 1]) || bytes[index - 1] == b':'))
        {
            index += 1;
            continue;
        }
        let mut cursor = index + 5;
        while cursor < bytes.len()
            && (hex_pair(bytes[cursor]) || bytes[cursor] == b':' || bytes[cursor] == b'.')
        {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'%') {
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric()
                    || matches!(bytes[cursor], b'.' | b'_' | b'-'))
            {
                cursor += 1;
            }
        }
        if bytes.get(cursor) == Some(&b'/') {
            let mut digits = cursor + 1;
            while digits < bytes.len() && bytes[digits].is_ascii_digit() {
                digits += 1;
            }
            if digits > cursor + 1 {
                cursor = digits;
            }
        }
        out.push_str(&text[copied..index]);
        out.push_str(IPV6_LABEL);
        copied = cursor;
        index = cursor;
    }
    out.push_str(&text[copied..]);
    out
}

fn redact_runs(text: &str, minimum: usize, class: fn(u8) -> bool, label: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        if !class(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && class(bytes[index]) {
            index += 1;
        }
        if index - start < minimum {
            continue;
        }
        out.push_str(&text[copied..start]);
        out.push_str(label);
        copied = index;
    }
    out.push_str(&text[copied..]);
    out
}

fn redact_base64(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        let class = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=');
        if !class(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        let mut upper = false;
        let mut lower = false;
        let mut digit = false;
        let mut symbol = false;
        while index < bytes.len() && class(bytes[index]) {
            let byte = bytes[index];
            upper |= byte.is_ascii_uppercase();
            lower |= byte.is_ascii_lowercase();
            digit |= byte.is_ascii_digit();
            symbol |= matches!(byte, b'+' | b'/' | b'=');
            index += 1;
        }
        let tokenish = symbol || (upper && lower && digit);
        if index - start < 32 || !tokenish {
            continue;
        }
        out.push_str(&text[copied..start]);
        out.push_str(TOKEN_LABEL);
        copied = index;
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor() -> Redactor {
        Redactor {
            homes: vec!["/root".to_string(), "/home/alice".to_string()],
            users: vec!["alice".to_string(), "root".to_string()],
            host: Some("workstation".to_string()),
            profiles: vec![
                ("game".to_string(), "<profile-1>".to_string()),
                ("game-prod".to_string(), "<profile-2>".to_string()),
            ],
        }
    }

    #[test]
    fn redacts_in_order_without_double_substitution() {
        let redacted = redactor().redact_text(
            "path=/home/alice/game\nuser=alice host=workstation\nmode=route include_lan=true",
        );
        assert!(redacted.contains("<home>/<profile-1>"), "{redacted}");
        assert!(!redacted.contains("/home/alice"), "{redacted}");
        assert!(redacted.contains("<user>"), "{redacted}");
        assert!(redacted.contains("<host>"), "{redacted}");
        assert!(redacted.contains("include_lan=true"), "{redacted}");
        assert!(!redacted.contains("<<"), "{redacted}");
    }

    #[test]
    fn longest_profile_name_wins() {
        let redacted = redactor().redact_text("game-prod and game");
        assert_eq!(redacted, "<profile-2> and <profile-1>");
    }

    #[test]
    fn redacts_secret_assignments_but_keeps_keys() {
        let redacted = redactor().redact_text(
            "password = \"hunter2\"\napi_key: abc123\nauthorization: Bearer abc.def\ninclude_lan = true",
        );
        assert!(redacted.contains("password = \"[REDACTED]\""), "{redacted}");
        assert!(redacted.contains("api_key: [REDACTED]"), "{redacted}");
        assert!(redacted.contains("authorization: [REDACTED]"), "{redacted}");
        assert!(redacted.contains("include_lan = true"), "{redacted}");
        assert!(!redacted.contains("hunter2"), "{redacted}");
    }

    #[test]
    fn redacts_tokens_and_macs() {
        let hex = "a".repeat(48);
        let token = "AbCdEf0123456789AbCdEf0123456789";
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "c2lnbmF0dXJl"
        );
        let redacted = redactor().redact_text(&format!(
            "{hex} {token} {jwt} 00:11:22:33:44:55 fe80::1%eth0"
        ));
        assert!(!redacted.contains(&hex), "{redacted}");
        assert!(!redacted.contains(token), "{redacted}");
        assert!(!redacted.contains(&jwt), "{redacted}");
        assert!(redacted.contains(MAC_LABEL), "{redacted}");
        assert!(redacted.contains(IPV6_LABEL), "{redacted}");
    }

    #[test]
    fn binary_input_is_not_rewritten() {
        assert!(redactor().redact(b"abc\0def").is_none());
    }
}
