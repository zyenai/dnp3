use crate::app::Iin2;
use crate::master::EventClasses;
use crate::outstation::database::details::event::buffer::{EventBuffer, InsertError};
use crate::outstation::database::details::range::static_db::{
    PointConfig, StaticDatabase, Updatable, UpdatableFlags,
};
use crate::outstation::database::read::ReadHeader;
use crate::outstation::database::{
    ClassZeroConfig, EventBufferConfig, EventMode, ResponseInfo, UpdateFlagsType, UpdateInfo,
    UpdateOptions,
};

use crate::app::measurement::{
    AnalogInput, AnalogOutputStatus, BinaryInput, BinaryOutputStatus, Counter,
    DoubleBitBinaryInput, Flags, FrozenCounter, Time, VirtualTerminal,
};
use crate::outstation::database::config::EventVirtualTerminalVariation;
use crate::outstation::database::details::attrs::map::SetMap;
use crate::outstation::database::EventClass;
use crate::outstation::{BufferState, OutstationApplication};
use scursor::WriteCursor;

use std::collections::BTreeMap;

pub(crate) struct Database {
    static_db: StaticDatabase,
    event_buffer: EventBuffer,
    attrs: super::attrs::AttrHandler,
    /// registered virtual terminal ports (g112/g113); maps port index -> event class.
    ///
    /// Virtual terminal data is event-only, so it does not live in the static database. The
    /// registry exists only to remember which event class a port's g113 events belong to.
    virtual_terminals: BTreeMap<u16, EventClass>,
}

impl Database {
    pub(crate) fn new(
        max_read_selection: Option<u16>,
        class_zero_config: ClassZeroConfig,
        config: EventBufferConfig,
    ) -> Self {
        Self {
            static_db: StaticDatabase::new(max_read_selection, class_zero_config),
            event_buffer: EventBuffer::new(config),
            attrs: super::attrs::AttrHandler::new(32),
            virtual_terminals: BTreeMap::new(),
        }
    }

    pub(crate) fn get_attr_map(&mut self) -> &mut SetMap {
        self.attrs.get_attr_map()
    }

    pub(crate) fn reset(&mut self) {
        self.static_db.reset();
        self.event_buffer.reset();
        self.attrs.reset();
    }

    pub(crate) fn set_analog_deadband(&mut self, index: u16, deadband: f64) -> bool {
        self.static_db.set_analog_deadband(index, deadband)
    }

    pub(crate) fn clear_written_events(
        &mut self,
        app: &mut dyn OutstationApplication,
    ) -> BufferState {
        self.event_buffer.clear_written(app);
        self.event_buffer.buffer_state()
    }

    pub(crate) fn unwritten_classes(&self) -> EventClasses {
        self.event_buffer.unwritten_classes()
    }

    pub(crate) fn is_overflown(&self) -> bool {
        self.event_buffer.is_overflown()
    }

    pub(crate) fn select_by_header(&mut self, header: ReadHeader) -> Iin2 {
        match header {
            ReadHeader::Static(header) => self.static_db.select(header),
            ReadHeader::Event(header) => {
                self.event_buffer.select_by_header(header);
                Iin2::default()
            }
            ReadHeader::Attr(header) => self.attrs.select(header),
        }
    }

    pub(crate) fn select_event_classes(&mut self, classes: EventClasses) -> usize {
        self.event_buffer.select_by_class(classes, None)
    }

    pub(crate) fn add<T>(&mut self, index: u16, config: PointConfig<T>) -> bool
    where
        T: Updatable,
    {
        self.static_db.add(index, config)
    }

    pub(crate) fn remove<T>(&mut self, index: u16) -> bool
    where
        T: Updatable,
    {
        self.static_db.remove::<T>(index)
    }

    pub(crate) fn get<T>(&self, index: u16) -> Option<T>
    where
        T: Updatable,
    {
        self.static_db.get::<T>(index)
    }

    pub(crate) fn update_flags(
        &mut self,
        index: u16,
        flags_type: UpdateFlagsType,
        flags: Flags,
        time: Option<Time>,
        options: UpdateOptions,
    ) -> UpdateInfo {
        match flags_type {
            UpdateFlagsType::BinaryInput => {
                self.update_flags_by_type::<BinaryInput>(index, flags, time, options)
            }
            UpdateFlagsType::DoubleBitBinaryInput => {
                self.update_flags_by_type::<DoubleBitBinaryInput>(index, flags, time, options)
            }
            UpdateFlagsType::BinaryOutputStatus => {
                self.update_flags_by_type::<BinaryOutputStatus>(index, flags, time, options)
            }
            UpdateFlagsType::Counter => {
                self.update_flags_by_type::<Counter>(index, flags, time, options)
            }
            UpdateFlagsType::FrozenCounter => {
                self.update_flags_by_type::<FrozenCounter>(index, flags, time, options)
            }
            UpdateFlagsType::AnalogInput => {
                self.update_flags_by_type::<AnalogInput>(index, flags, time, options)
            }
            UpdateFlagsType::AnalogOutputStatus => {
                self.update_flags_by_type::<AnalogOutputStatus>(index, flags, time, options)
            }
        }
    }

    pub(crate) fn update_flags_by_type<T: UpdatableFlags>(
        &mut self,
        index: u16,
        flags: Flags,
        timestamp: Option<Time>,
        options: UpdateOptions,
    ) -> UpdateInfo {
        match self.static_db.get::<T>(index) {
            None => UpdateInfo::NoPoint,
            Some(mut x) => {
                x.update_flags(flags, timestamp);
                self.update::<T>(&x, index, options)
            }
        }
    }

    pub(crate) fn update<T>(&mut self, value: &T, index: u16, options: UpdateOptions) -> UpdateInfo
    where
        T: Updatable,
    {
        let (exists, event_data) = self.static_db.update(value, index, options);

        // if an event should be produced, insert it into the buffer
        if let Some((variation, class)) = event_data {
            // Overflow is handled in the event buffer
            return match self.event_buffer.insert(index, class, value, variation) {
                Ok(x) => UpdateInfo::Created(x),
                Err(InsertError::TypeMaxIsZero) => UpdateInfo::NoEvent,
                Err(InsertError::Overflow { created, discarded }) => {
                    UpdateInfo::Overflow { created, discarded }
                }
            };
        }

        if exists {
            UpdateInfo::NoEvent
        } else {
            UpdateInfo::NoPoint
        }
    }

    /// Register a virtual terminal port. Returns false if a port with this index already exists.
    pub(crate) fn add_virtual_terminal(&mut self, port: u16, class: EventClass) -> bool {
        if self.virtual_terminals.contains_key(&port) {
            return false;
        }
        self.virtual_terminals.insert(port, class);
        true
    }

    /// Remove a virtual terminal port. Returns true if the port existed.
    ///
    /// Any g113 events already buffered for the port are still reported normally.
    pub(crate) fn remove_virtual_terminal(&mut self, port: u16) -> bool {
        self.virtual_terminals.remove(&port).is_some()
    }

    /// Publish a Group 113 virtual terminal event for a registered port.
    ///
    /// Virtual terminal data is event-only (no static value is stored), so there is nothing to
    /// compare against: `EventMode::Detect` and `EventMode::Force` both emit an event, while
    /// `EventMode::Suppress` emits none.
    pub(crate) fn update_virtual_terminal(
        &mut self,
        port: u16,
        value: &VirtualTerminal,
        options: UpdateOptions,
    ) -> UpdateInfo {
        let Some(&class) = self.virtual_terminals.get(&port) else {
            return UpdateInfo::NoPoint;
        };

        if options.event_mode == EventMode::Suppress {
            return UpdateInfo::NoEvent;
        }

        match self
            .event_buffer
            .insert(port, class, value, EventVirtualTerminalVariation)
        {
            Ok(x) => UpdateInfo::Created(x),
            Err(InsertError::TypeMaxIsZero) => UpdateInfo::NoEvent,
            Err(InsertError::Overflow { created, discarded }) => {
                UpdateInfo::Overflow { created, discarded }
            }
        }
    }

    pub(crate) fn write_response_headers(&mut self, cursor: &mut WriteCursor) -> ResponseInfo {
        // first we write events
        let result = self.event_buffer.write_events(cursor);
        let has_events = match result {
            Ok(count) => count > 0,
            Err(count) => count > 0,
        };

        // next write static data
        let complete = if result.is_err() {
            // unable to write all the events in this response, so we can't write any static data
            false
        } else {
            // write all events to we can try to write all static data
            self.static_db.write(cursor).is_ok()
        };

        // next write device attributes
        let complete = if complete {
            self.attrs.write(cursor)
        } else {
            false
        };

        ResponseInfo {
            has_events,
            complete,
        }
    }

    pub(crate) fn write_events_only(&mut self, cursor: &mut WriteCursor) -> usize {
        // doesn't matter if we wrote all of them or not
        match self.event_buffer.write_events(cursor) {
            Ok(x) => x,
            Err(x) => x,
        }
    }
}
