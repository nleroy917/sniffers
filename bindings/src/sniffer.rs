use pyo3::prelude::*;

use sniffers::Sniffer;

#[pyclass(name="Sniffer")]
pub struct PySniffer {
    sniffer: Sniffer,
}

#[pymethods]
impl PySniffer {
    #[new]
    fn new(path: Option<String>) -> Self {
        let sniffer = Sniffer::default().path(path.unwrap_or_else(|| ".".to_string()));
        PySniffer { sniffer }
    }

    fn sniff(&self) -> PyResult<Vec<String>> {
        Ok(self.sniffer.sniff().unwrap())
    }

    fn index(&self) -> PyResult<()> {
        self.sniffer.index().unwrap();
        Ok(())
    }
}