use std::fmt;
use thiserror;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Hash, Clone)]
pub enum SymbolizationError {
    #[error("Symbolization error {0}")]
    Generic(String),
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Default)]
pub struct Frame {
    /// Address from the process, as collected from the BPF program.
    pub virtual_address: u64,
    /// The offset in the object file after converting the virtual_address its relative position.
    pub file_offset: Option<u64>,
    /// If symbolized, the result will be present here with the function name and whether the function
    /// was inlined.
    pub symbolization_result: Option<Result<(String, bool), SymbolizationError>>,
}

impl fmt::Display for Frame {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &self.symbolization_result {
            Some(Ok((name, inlined))) => {
                let inline_str = if *inlined { "[inlined] " } else { "" };
                write!(fmt, "{}{}", inline_str, name)
            }
            Some(Err(e)) => {
                write!(fmt, "error: {:?}", e)
            }
            None => {
                write!(fmt, "frame not symbolized")
            }
        }
    }
}

impl Frame {
    pub fn with_error(virtual_address: u64, msg: String) -> Self {
        Self {
            virtual_address,
            file_offset: None,
            symbolization_result: Some(Err(SymbolizationError::Generic(msg))),
        }
    }
}
