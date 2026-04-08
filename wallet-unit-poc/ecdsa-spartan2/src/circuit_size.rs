use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitSize {
    /// Default JWT circuit (maxMessageLength=1920)
    Jwt,
    Kb1,
    Kb2,
    Kb4,
    Kb8,
}

impl CircuitSize {
    pub const ALL: [CircuitSize; 4] = [
        CircuitSize::Kb1,
        CircuitSize::Kb2,
        CircuitSize::Kb4,
        CircuitSize::Kb8,
    ];

    pub fn circuit_name(self) -> &'static str {
        match self {
            CircuitSize::Jwt => "jwt",
            CircuitSize::Kb1 => "jwt_1k",
            CircuitSize::Kb2 => "jwt_2k",
            CircuitSize::Kb4 => "jwt_4k",
            CircuitSize::Kb8 => "jwt_8k",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CircuitSize::Jwt => "default",
            CircuitSize::Kb1 => "1k",
            CircuitSize::Kb2 => "2k",
            CircuitSize::Kb4 => "4k",
            CircuitSize::Kb8 => "8k",
        }
    }

    pub fn max_message_length(self) -> usize {
        match self {
            CircuitSize::Jwt => 1920,
            CircuitSize::Kb1 => 1280,
            CircuitSize::Kb2 => 2048,
            CircuitSize::Kb4 => 4096,
            CircuitSize::Kb8 => 8192,
        }
    }

    pub fn max_b64_payload_length(self) -> usize {
        match self {
            CircuitSize::Jwt => 1900,
            CircuitSize::Kb1 => 960,
            CircuitSize::Kb2 => 2000,
            CircuitSize::Kb4 => 4000,
            CircuitSize::Kb8 => 8000,
        }
    }

    pub fn max_matches(self) -> usize {
        4
    }
    pub fn max_substring_length(self) -> usize {
        50
    }

    pub fn max_claims_length(self) -> usize {
        128
    }
}

impl Default for CircuitSize {
    fn default() -> Self {
        CircuitSize::Jwt
    }
}

impl fmt::Display for CircuitSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CircuitSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" | "jwt" => Ok(CircuitSize::Jwt),
            "1k" => Ok(CircuitSize::Kb1),
            "2k" => Ok(CircuitSize::Kb2),
            "4k" => Ok(CircuitSize::Kb4),
            "8k" => Ok(CircuitSize::Kb8),
            other => Err(format!(
                "Unknown circuit size '{}'. Valid values: 1k, 2k, 4k, 8k",
                other
            )),
        }
    }
}
