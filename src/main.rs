use std::{net::{TcpStream, SocketAddrV4, SocketAddr}, io::{Write, Read}, str::FromStr, time::Duration};

use anyhow::bail;
use trust_dns_resolver::{Resolver, config::{ResolverConfig, ResolverOpts}};

fn main() {
    let Some(mut address) = std::env::args().nth(1) else { panic!("address not found") };
    let Some(port) = std::env::args().nth(2) else { panic!("port not found") };

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    if let Ok(response) = resolver.srv_lookup(format!("_minecraft._tcp.{address}")) {
        for record in response.as_lookup().record_iter() {
            let Some(data) = record.data() else { break };
            let Some(srv) = data.as_srv() else { break };

            address = srv.target().to_string();
        }
    }

    if let Ok(mut stream) = TcpStream::connect(format!("{address}:{port}")) {
        let addr = stream.peer_addr().unwrap();

        println!("Connected to {}", stream.peer_addr().unwrap().to_string());
        
        HandshakePacket {
            protocol: 763,
            address,
            port: addr.port(),
            next: 1
        }.encode(&mut stream).unwrap();

        StatusRequestPacket{}.encode(&mut stream).unwrap();

        println!("listening");

        loop {
            let mut raw_packet = Vec::new();
            let mut should_break = false;

            loop {
                let mut buffer = [0u8; 1024];
                if should_break { stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap(); } else { stream.set_read_timeout(Some(Duration::from_secs(300))).unwrap(); }
                let Ok(length) = stream.read(&mut buffer) else { break };

                let bytes = &mut buffer[..length];
    
                raw_packet.write(&bytes).unwrap();

                if length < buffer.len() {
                    if should_break && length <= 0 {
                        break
                    }

                    should_break = true;
                } else {
                    should_break = false;
                }
            }

            // println!("{:02X?}", &raw_packet);

            if let Ok(packet) = PingPacket::decode(&mut &raw_packet[..]) {
                dbg!(packet);
            }

            if let Ok(packet) = StatusResponsePacket::decode(&mut &raw_packet[..]) {
                dbg!(packet);
                PingPacket::new(25522).encode(&mut stream).unwrap();
            }
        }
    }
}

trait PacketDecoder {
    fn decode<R: Read>(reader: &mut R) -> anyhow::Result<Self>
    where
        Self: Sized;
}

trait PacketEncoder {
    fn encode<W: Write>(&self, writer: &mut W) -> anyhow::Result<()>;
}

trait LengthPrefix: Write {
    fn write_length(&mut self, buf: &[u8]) -> anyhow::Result<()>;
    fn write_varint(&mut self, value: u32) -> anyhow::Result<()>;
    fn write_varint_length(&mut self, value: u32) -> anyhow::Result<()>;
}

trait SingleByte {
    fn read_byte(&mut self) -> anyhow::Result<u8>;
}

impl<R: Read> SingleByte for R {
    fn read_byte(&mut self) -> anyhow::Result<u8> {
        let mut byte = [0u8; 1];
        self.read(&mut byte)?;
        Ok(byte[0])
    }
}

impl<W: Write> LengthPrefix for W {
    fn write_length(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        // let len = buf.len().to_be_bytes().iter().filter(|&&v| v != 0x00).cloned().collect::<Vec<u8>>();
        let mut len = Vec::new();
        varint_rs::VarintWriter::write_u32_varint(&mut len, buf.len() as u32)?;

        self.write(&len)?;
        self.write(buf)?;

        Ok(())
    }

    fn write_varint(&mut self, value: u32) -> anyhow::Result<()> {
        let mut buffer = Vec::new();
        varint_rs::VarintWriter::write_u32_varint(&mut buffer, value)?;

        self.write(&buffer)?;

        Ok(())
    }
    
    fn write_varint_length(&mut self, value: u32) -> anyhow::Result<()> {
        let mut buffer = Vec::new();
        varint_rs::VarintWriter::write_u32_varint(&mut buffer, value)?;

        self.write_length(&buffer)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum PacketID {
    Handshake = 0x00,
    Ping = 0x01,
}

impl PacketDecoder for PacketID {
    fn decode<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let byte = reader.read_byte()?;
        
        match byte {
            byte if Self::Handshake as u8 == byte => Ok(Self::Handshake),
            byte if Self::Ping as u8 == byte => Ok(Self::Ping),
            _ => { unimplemented!("0x{:02X?} \"Packet Unimplemented\"", byte) }
        }
    }
}

impl PacketEncoder for PacketID {
    fn encode<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.write(&[self.to_owned() as u8])?;

        Ok(())
    }
}

#[derive(Debug)]
struct PingPacket {
    payload: i64
}

impl PingPacket {
    fn new(payload: i64) -> Self {
        Self { payload }
    }
}

impl PacketEncoder for PingPacket {
    fn encode<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        let mut buffer = Vec::new();

        PacketID::encode(&PacketID::Ping, &mut buffer).unwrap();
        buffer.write(&self.payload.to_be_bytes())?;

        writer.write_length(&mut buffer)
    }
}

impl PacketDecoder for PingPacket {
    fn decode<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let length = varint_rs::VarintReader::read_u32_varint(reader)? as usize;

        let mut buffer = vec![0u8; length];
        reader.read_exact(&mut buffer)?;
        let mut buffer = &buffer[..length];

        let Ok(PacketID::Ping) = PacketID::decode(&mut buffer) else { bail!("not ping packet") };

        let mut payload = [0u8; 8];
        buffer.read(&mut payload)?;
        let payload = i64::from_be_bytes(payload);

        Ok(Self { payload })
    }
}

struct HandshakePacket {
    protocol: u32,
    address: String,
    port: u16,
    next: u32
}

impl PacketEncoder for HandshakePacket {
    fn encode<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        let mut buffer = Vec::new();

        PacketID::encode(&PacketID::Handshake, &mut buffer)?;

        buffer.write_varint(self.protocol)?;
        buffer.write_length(self.address.as_bytes())?;
        buffer.write(&self.port.to_be_bytes())?;
        buffer.write_varint(self.next)?;

        writer.write_length(&buffer)
    }
}

struct StatusRequestPacket;

impl PacketEncoder for StatusRequestPacket {
    fn encode<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        let mut buffer = Vec::new();

        PacketID::encode(&PacketID::Handshake, &mut buffer)?;

        writer.write_length(&buffer)
    }
}

#[derive(Debug)]
struct StatusResponsePacket {
    response: String
}

impl PacketDecoder for StatusResponsePacket {
    fn decode<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let length = varint_rs::VarintReader::read_u32_varint(reader)? as usize;

        let mut buffer = vec![0u8; length];
        reader.read_exact(&mut buffer)?;
        let mut buffer = &buffer[..length];

        let Ok(PacketID::Handshake) = PacketID::decode(&mut buffer) else { bail!("not status response packet") };

        let length = varint_rs::VarintReader::read_u32_varint(&mut buffer)? as usize;
        let mut response = vec![0u8; length];
        buffer.read_exact(&mut response)?;
        let response = String::from_utf8(response)?;

        Ok(Self { response })
    }
}
