use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

// Constante de magic PCAP native (little-endian). La variante swapped
// (`PCAP_MAGIC_SWAPPED`) est gérée par les outils type Wireshark ; cette
// implémentation écrit toujours en ordre natif, aussi seule la valeur native
// est utilisée.
const PCAP_MAGIC_NATIVE: u32 = 0xA1B2C3D4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAP_LEN: u32 = 65535;
const PCAP_LINKTYPE_ETHERNET: u32 = 1;

#[derive(Debug, Clone)]
pub struct PcapPacket {
    pub timestamp_ms: u64,
    pub length: u32,
    pub data: Vec<u8>,
}

pub struct PcapWriter {
    writer: BufWriter<File>,
    path: PathBuf,
    packet_count: u32,
}

impl PcapWriter {
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        let mut writer = BufWriter::new(file);

        // Global header PCAP (24 octets)
        writer.write_all(&PCAP_MAGIC_NATIVE.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&[0u8; 8])?; // thiszone + sigfigs (zéro)
        writer.write_all(&PCAP_SNAP_LEN.to_le_bytes())?;
        writer.write_all(&PCAP_LINKTYPE_ETHERNET.to_le_bytes())?;
        writer.flush()?;

        Ok(Self {
            writer,
            path,
            packet_count: 0,
        })
    }

    pub fn write_raw_packet(&mut self, timestamp_ms: u64, raw_bytes: &[u8]) -> io::Result<()> {
        let ts_sec = (timestamp_ms / 1000) as u32;
        let ts_usec = ((timestamp_ms % 1000) * 1000) as u32;
        let incl_len = raw_bytes.len() as u32;
        let orig_len = incl_len;

        // Packet header (16 octets)
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&incl_len.to_le_bytes())?;
        self.writer.write_all(&orig_len.to_le_bytes())?;
        self.writer.write_all(raw_bytes)?;
        self.packet_count += 1;

        if self.packet_count.is_multiple_of(100) {
            self.writer.flush()?;
        }

        Ok(())
    }

    pub fn write_parsed_packet(&mut self, packet: &PcapPacket) -> io::Result<()> {
        self.write_raw_packet(packet.timestamp_ms, &packet.data)
    }

    pub fn finalize(&mut self) -> io::Result<u32> {
        self.writer.flush()?;
        Ok(self.packet_count)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn packet_count(&self) -> u32 {
        self.packet_count
    }

    pub fn build_pseudo_ethernet(
        src_ip: &str,
        dst_ip: &str,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let src: std::net::Ipv4Addr = src_ip
            .parse()
            .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let dst: std::net::Ipv4Addr = dst_ip
            .parse()
            .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));

        let mut frame = Vec::with_capacity(14 + 20 + payload.len());

        // Ethernet header: dst(6) + src(6) + type(2)
        frame.extend_from_slice(&[0xff; 6]); // broadcast dst
        frame.extend_from_slice(&[0x00; 6]); // src (anonymisé)
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 header simplifié (20 octets, sans options)
        let total_len = 20 + payload.len();
        frame.push(0x45); // version + IHL
        frame.push(0x00); // DSCP/ECN
        frame.extend_from_slice(&(total_len as u16).to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes()); // identification
        frame.extend_from_slice(&0x4000u16.to_le_bytes()); // flags: DF
        frame.push(64); // TTL
        frame.push(protocol);
        frame.extend_from_slice(&0u16.to_le_bytes()); // checksum (zero)
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());

        frame.extend_from_slice(payload);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_pcap_write_and_read_header() {
        let dir = std::env::temp_dir().join("netsentinel_pcap_test");
        let path = dir.join("test.pcap");
        let mut writer = PcapWriter::create(&path).unwrap();

        let fake_packet = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x08, 0x00, // IPv4
            0x45, 0x00, // version + IHL
        ];

        writer
            .write_raw_packet(1700000000123, &fake_packet)
            .unwrap();
        writer
            .write_raw_packet(1700000000456, &fake_packet)
            .unwrap();
        let count = writer.finalize().unwrap();

        assert_eq!(count, 2);

        let mut file = File::open(&path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        // Global header = 24 octets, chaque paquet = 16 header + len(payload)
        let expected_len = 24 + (16 + fake_packet.len()) * 2;
        assert_eq!(contents.len(), expected_len);
        assert_eq!(&contents[0..4], &PCAP_MAGIC_NATIVE.to_le_bytes());

        // Vérifie le nom original et le timestamp du premier paquet
        let ts_sec_off = 24;
        let ts_sec = u32::from_le_bytes([
            contents[ts_sec_off],
            contents[ts_sec_off + 1],
            contents[ts_sec_off + 2],
            contents[ts_sec_off + 3],
        ]);
        assert_eq!(ts_sec, 1700000000);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_build_pseudo_ethernet() {
        let frame = PcapWriter::build_pseudo_ethernet("192.168.1.1", "10.0.0.1", 6, &[0xAA; 10]);
        assert_eq!(frame.len(), 14 + 20 + 10);
        assert_eq!(&frame[12..14], &[0x08, 0x00]); // IPv4
        assert_eq!(frame[23], 6); // TCP
    }
}
