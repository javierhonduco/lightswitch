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
    /// The offset in the object file after converting the virtual_address its
    /// relative position.
    pub file_offset: Option<u64>,
    /// If symbolized, the result will be present here with the function name
    /// and whether the function was inlined.
    pub symbolization_result: Option<Result<SymbolizedFrame, SymbolizationError>>,
}

/// A symbolized frame, which might or might not the filename or line number,
/// depending on the symbolization data source.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Default)]
pub struct SymbolizedFrame {
    pub name: String,
    pub inlined: bool,
    pub filename: Option<String>,
    pub line: Option<u32>,
}

impl SymbolizedFrame {
    pub fn new(name: String, inlined: bool, filename: Option<String>, line: Option<u32>) -> Self {
        SymbolizedFrame {
            name,
            inlined,
            filename,
            line,
        }
    }
}

impl Frame {
    /// Returns the formatted frame showing only the function names if
    /// `only_show_function_name` is true otherwise it will show the file
    /// and line number if available.
    pub fn format_all_info(&self, only_show_function_name: bool) -> String {
        match &self.symbolization_result {
            Some(Ok(SymbolizedFrame {
                name,
                inlined,
                filename,
                line,
            })) => {
                let mut res = String::new();

                let inline_str = if *inlined { "[inlined] " } else { "" };
                res.push_str(&format!("{inline_str}{name}"));

                if !only_show_function_name {
                    res.push(' ');
                    let filename = filename.clone().unwrap_or("<no file>".to_string());
                    let line = if let Some(num) = line {
                        num.to_string()
                    } else {
                        "<no line>".to_string()
                    };
                    res.push_str(&format!("({filename}:{line})"))
                }

                res
            }
            Some(Err(e)) => {
                format!("error: {e:?}")
            }
            None => "frame not symbolized".to_string(),
        }
    }
}

impl fmt::Display for Frame {
    /// Only writes the function name.
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.format_all_info(true))
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
