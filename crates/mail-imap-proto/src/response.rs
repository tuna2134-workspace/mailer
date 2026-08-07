#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok,
    No,
    Bad,
}

impl Status {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::No => "NO",
            Self::Bad => "BAD",
        }
    }
}

#[must_use]
pub fn greeting(capabilities: &[String]) -> String {
    format!(
        "* OK [CAPABILITY {}] maild ready\r\n",
        capabilities.join(" ")
    )
}

#[must_use]
pub fn tagged(tag: &str, status: Status, text: &str) -> String {
    format!("{tag} {} {}\r\n", status.as_str(), sanitize(text))
}

#[must_use]
pub fn untagged(text: &str) -> String {
    format!("* {}\r\n", sanitize(text))
}

#[must_use]
pub fn continuation(text: &str) -> String {
    format!("+ {}\r\n", sanitize(text))
}

fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}
