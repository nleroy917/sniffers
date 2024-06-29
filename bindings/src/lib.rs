mod sniffer;

use pyo3::prelude::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A Python module implemented in Rust.
#[pymodule]
fn sniffers(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<sniffer::PySniffer>()?;
    m.add("__version__", VERSION)?;
    Ok(())
}
