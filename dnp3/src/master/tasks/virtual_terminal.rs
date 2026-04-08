use crate::app::format::write::HeaderWriter;
use crate::app::parse::parser::Response;
use crate::app::FunctionCode;
use crate::master::promise::Promise;
use crate::master::tasks::{AppTask, NonReadTask, Task};
use crate::master::{TaskError, WriteError};

/// Task that writes a Group 112 VarX (Virtual Terminal Output Block) object to the outstation.
///
/// G112 carries binary data from master to outstation via a WRITE request.
/// The point index (port) identifies the virtual terminal port.
pub(crate) struct WriteVirtualTerminalTask {
    /// VT port index (DNP3 point number for the virtual terminal)
    port: u8,
    /// Data payload (max 255 bytes)
    data: Vec<u8>,
    promise: Promise<Result<(), WriteError>>,
}

impl From<WriteVirtualTerminalTask> for Task {
    fn from(value: WriteVirtualTerminalTask) -> Self {
        Task::App(AppTask::NonRead(NonReadTask::VirtualTerminalWrite(value)))
    }
}

impl WriteVirtualTerminalTask {
    pub(crate) fn new(port: u8, data: Vec<u8>, promise: Promise<Result<(), WriteError>>) -> Self {
        Self {
            port,
            data,
            promise,
        }
    }

    pub(crate) const fn function(&self) -> FunctionCode {
        FunctionCode::Write
    }

    pub(crate) fn write(&self, writer: &mut HeaderWriter) -> Result<(), scursor::WriteError> {
        writer.write_virtual_terminal_output(self.port, &self.data)
    }

    pub(crate) fn on_task_error(self, err: TaskError) {
        self.promise.complete(Err(err.into()))
    }

    pub(crate) fn handle(self, response: Response) -> Result<Option<NonReadTask>, TaskError> {
        if response.raw_objects.is_empty() {
            self.promise.complete(Ok(()));
            Ok(None)
        } else {
            self.promise
                .complete(Err(WriteError::Task(TaskError::UnexpectedResponseHeaders)));
            Err(TaskError::UnexpectedResponseHeaders)
        }
    }
}
