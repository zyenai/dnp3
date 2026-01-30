use crate::app::format::write::HeaderWriter;
use crate::app::parse::parser::Response;
use crate::app::FunctionCode;
use crate::master::promise::Promise;
use crate::master::request::VirtualTerminalHeader;
use crate::master::tasks::{AppTask, NonReadTask, Task};
use crate::master::{TaskError, WriteError};

pub(crate) struct WriteVirtualTerminalTask {
    headers: Vec<VirtualTerminalHeader>,
    promise: Promise<Result<(), WriteError>>,
}

impl From<WriteVirtualTerminalTask> for Task {
    fn from(value: WriteVirtualTerminalTask) -> Self {
        Task::App(AppTask::NonRead(NonReadTask::VirtualTerminal(value)))
    }
}

impl WriteVirtualTerminalTask {
    pub(crate) fn new(
        headers: Vec<VirtualTerminalHeader>,
        promise: Promise<Result<(), WriteError>>,
    ) -> Self {
        Self { headers, promise }
    }

    pub(crate) const fn function(&self) -> FunctionCode {
        FunctionCode::Write
    }

    pub(crate) fn write(&self, writer: &mut HeaderWriter) -> Result<(), scursor::WriteError> {
        for header in self.headers.iter() {
            // Write Group 112 with variation = data length
            // Using indexed format with two-byte prefix
            writer.write_range_only(
                crate::app::Variation::Group112(header.data.len() as u8),
                header.port,
                header.port,
            )?;
            writer.write_bytes(&header.data)?;
        }
        Ok(())
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
