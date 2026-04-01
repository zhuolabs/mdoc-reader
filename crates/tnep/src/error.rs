use std::panic::Location;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("transport error at {location}: {source}")]
    Transport {
        #[source]
        source: anyhow::Error,
        location: &'static Location<'static>,
    },
    #[error("invalid message at {location}")]
    InvalidMessage {
        location: &'static Location<'static>,
    },
    #[error("service not found at {location}: {service_name}")]
    ServiceNotFound {
        service_name: String,
        location: &'static Location<'static>,
    },
    #[error("protocol error at {location}")]
    ProtocolError {
        location: &'static Location<'static>,
    },
}

impl Error {
    #[track_caller]
    pub fn transport(source: anyhow::Error) -> Self {
        Self::Transport {
            source,
            location: Location::caller(),
        }
    }

    #[track_caller]
    pub fn invalid_message() -> Self {
        Self::InvalidMessage {
            location: Location::caller(),
        }
    }

    #[track_caller]
    pub fn service_not_found(service_name: impl Into<String>) -> Self {
        Self::ServiceNotFound {
            service_name: service_name.into(),
            location: Location::caller(),
        }
    }

    #[track_caller]
    pub fn protocol_error() -> Self {
        Self::ProtocolError {
            location: Location::caller(),
        }
    }
}
