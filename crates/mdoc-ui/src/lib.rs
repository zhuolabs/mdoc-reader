use mdoc_core::DeviceResponse;
use mdoc_reader_flow::ReaderFlowEvent;

pub trait MdocResultUi<V> {
    type Error;

    fn render_result(
        &mut self,
        response: &DeviceResponse,
        validation: &V,
    ) -> Result<(), Self::Error>;
}

pub trait FlowEventUi {
    type Error;

    fn on_flow_event(&self, event: ReaderFlowEvent) -> Result<(), Self::Error>;
}
