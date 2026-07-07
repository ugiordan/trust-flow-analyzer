use std::collections::HashMap;

pub struct User {
    pub email: String,
    pub groups: Vec<String>,
}

pub fn validate_token(token: Option<&str>) -> Result<User, String> {
    let token = token.ok_or("missing token")?;
    let user = decode_token(token)?;
    Ok(user)
}

fn decode_token(token: &str) -> Result<User, String> {
    if !token.starts_with("tok_") {
        return Err("invalid token format".to_string());
    }
    Ok(User {
        email: "user@example.com".to_string(),
        groups: vec![],
    })
}

pub fn authorize(user: &User, allowed_groups: &[String]) -> bool {
    if allowed_groups.is_empty() {
        return true; // empty groups = allow all
    }
    user.groups.iter().any(|g| allowed_groups.contains(g))
}

pub fn check_groups(user: &User, groups: &[String]) -> bool {
    if groups.is_empty() {
        return true;
    }
    false
}
