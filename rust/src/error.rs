//! The errors the core raises, each mapped to the Python exception python_sbom._errors defines for it.

use pyo3::PyErr;
use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;

#[derive(Debug)]
pub enum Error {
    /// python_sbom._errors.SbomError
    Sbom(String),
    /// python_sbom._errors.SettingsError
    Settings(String),
    /// python_sbom._errors.WheelError
    Wheel(String),
    /// packaging.requirements.InvalidRequirement, which callers raised unwrapped
    InvalidRequirement(String),
    Value(String),
    Key(String),
    Type(String),
    Io(std::io::Error),
    Python(PyErr),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PyErr> for Error {
    fn from(error: PyErr) -> Self {
        Self::Python(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sbom(message)
            | Self::Settings(message)
            | Self::Wheel(message)
            | Self::InvalidRequirement(message)
            | Self::Value(message)
            | Self::Key(message)
            | Self::Type(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Python(error) => write!(formatter, "{error}"),
        }
    }
}

fn raise(py: Python<'_>, class: &str, message: String) -> PyErr {
    match py.import("python_sbom._errors").and_then(|module| module.getattr(class)) {
        Ok(kind) => PyErr::from_type(kind.cast_into().expect("an exception class"), message),
        Err(error) => error,
    }
}

impl From<Error> for PyErr {
    fn from(error: Error) -> Self {
        Python::attach(|py| match error {
            Error::Sbom(message) => raise(py, "SbomError", message),
            Error::Settings(message) => raise(py, "SettingsError", message),
            Error::Wheel(message) => raise(py, "WheelError", message),
            Error::InvalidRequirement(message) => {
                match py.import("python_sbom._errors").and_then(|module| module.getattr("InvalidRequirement")) {
                    Ok(kind) => PyErr::from_type(kind.cast_into().expect("an exception class"), message),
                    Err(error) => error,
                }
            }
            Error::Value(message) => PyValueError::new_err(message),
            Error::Key(message) => PyKeyError::new_err(message),
            Error::Type(message) => PyTypeError::new_err(message),
            Error::Io(error) => PyErr::from(error),
            Error::Python(error) => error,
        })
    }
}

