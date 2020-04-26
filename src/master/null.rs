use crate::app::header::ResponseHeader;
use crate::app::parse::parser::HeaderCollection;
use crate::master::handle::{AssociationHandler, ResponseHandler};

#[derive(Copy, Clone)]
pub struct NullHandler;

impl NullHandler {
    pub fn boxed() -> Box<NullHandler> {
        Box::new(Self {})
    }
}

impl ResponseHandler for NullHandler {
    fn handle(&mut self, _source: u16, _header: ResponseHeader, _headers: HeaderCollection) {}
}

impl AssociationHandler for NullHandler {}
