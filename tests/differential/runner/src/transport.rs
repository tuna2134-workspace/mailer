use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(25);
pub const CASE_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_RESPONSE: usize = 128 * 1024;
pub const MAX_TRANSCRIPT: usize = 256 * 1024;

pub enum Wire {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Wire {
    pub fn connect(address: (&str, u16)) -> io::Result<Self> {
        let socket = address
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no target address"))?;
        let stream = TcpStream::connect_timeout(&socket, IO_TIMEOUT)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(Self::Plain(stream))
    }

    pub fn start_tls(self, hostname: &str, ca_path: &str) -> io::Result<Self> {
        let Self::Plain(stream) = self else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS already active",
            ));
        };
        let mut roots = RootCertStore::empty();
        let mut reader = BufReader::new(File::open(ca_path)?);
        let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        let (added, _) = roots.add_parsable_certificates(certificates);
        if added == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty test CA"));
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(hostname.to_owned())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let connection = ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
        Ok(Self::Tls(Box::new(StreamOwned::new(connection, stream))))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(Shutdown::Both),
            Self::Tls(stream) => stream.sock.shutdown(Shutdown::Both),
        }
    }

    pub fn limit_to_deadline(&self, deadline: std::time::Instant) -> io::Result<()> {
        let timeout = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "testcase timeout"))?
            .min(IO_TIMEOUT);
        let socket = match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        };
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))
    }
}

impl Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

pub fn send_chunks(
    wire: &mut Wire,
    chunks: &[Vec<u8>],
    transcript: &mut Vec<u8>,
) -> io::Result<()> {
    for chunk in chunks {
        if transcript.len().saturating_add(chunk.len()) > MAX_TRANSCRIPT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transcript limit",
            ));
        }
        wire.write_all(chunk)?;
        transcript.extend_from_slice(chunk);
    }
    wire.flush()
}

pub fn read_line(wire: &mut Wire) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while line.len() < MAX_RESPONSE {
        match wire.read(&mut byte) {
            Ok(0) if line.is_empty() => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
            }
            Ok(0) => return Ok(line),
            Ok(_) => {
                line.push(byte[0]);
                if line.ends_with(b"\n") {
                    return Ok(line);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "response limit"))
}
