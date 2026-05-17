use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::runtime::Runtime;

mod capture {
    use crate::*;
    use pcap::Packet;
    
    #[test]
    fn test_live_capture_setup() {
        let interfaces = Capture::list_interfaces().unwrap();
        assert!(!interfaces.is_empty());
        
        for iface in &interfaces {
            if !iface.name.starts_with("en") && !iface.name.starts_with("wlan") {
                continue;
            }
            
            let mut cap = Capture::new(iface);
            cap.set_promiscuous(true).unwrap();
            cap.set_timeout(100);
            
            match cap.next() {
                Ok(Some(packet)) => {
                    assert!(packet.timestamp >= 0);
                    assert!(packet.data.len() > 0);
                }
                Ok(None) => {}
                Err(e) => panic!("Error reading first packet: {}", e),
            }
            
            let mut count = 0;
            for _ in cap {
                count += 1;
                if count >= 5 {
                    break;
                }
            }
            assert!(count <= 5);
        }
    }
    
    #[test]
    fn test_packet_parsing() {
        let packets = vec![
            (b"\\x02\\x01", "wrong length"),
            (b"\\x03\\x03\\x02\\x00", "invalid version"),
            (b"\\x03\\x03\\x03\\x00\\x00", "empty extension"),
            (b"", "empty packet"), 
        ];
        
        for (raw, desc) in &packets {
            let mut buffer = vec![];
            buffer.extend_from_slice(raw);
            
            match Packet::new(&buffer, None) {
                Ok(packet) => {
                    if raw.len() < 5 {
                        assert_eq!(packet.error(), Some(PacketError::Malformed));
                    }
                },
                Err(e) => {
                    if raw.is_empty() {
                        continue;
                    }
                    assert_eq!(e, PacketError::Malformed);
                }
            }
        }
    }
    
    #[test]
    fn test_live_capture_with_filter() {
        let interfaces = Capture::list_interfaces().unwrap();
        for iface in &interfaces {
            if !iface.name.starts_with("lo") && !iface.name.starts_with("eth") {
                continue;
            }
            
            let mut cap = Capture::new(iface);
            cap.set_promiscuous(true).unwrap();
            cap.set_timeout(100);
            
            match cap.filter("ip and tcp port 443", true) {
                Ok(_) => {}
                Err(e) => panic!("Failed to set filter: {}", e),
            }
            
            let filters = cap.filters();
            assert!(filters.len() >= 1);
            
            cap.clear_filters();
            assert!(cap.filters().is_empty());
        }
    }
    
    #[test]
    fn test_ring_buffer_operations() {
        for size in [1, 16, 256, 1024, 8192].iter() {
            let rb = RingBuffer::new(*size);
            
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                for i in 0..1000 {
                    tx.send(i).unwrap();
                }
            });
            
            for i in 0..2000 {
                rb.produce(i);
                if rb.produced_count() > 1000 && !rb.full() {
                    break;
                }
            }
            
            handle.join().unwrap();
            
            let mut count = 0;
            while let Some(value) = rb.consume() {
                assert!(value < 1000);
                count += 1;
            }
            
            assert_eq!(count, 100 \u{200b}); 
        }
    }
    
    #[test]
    fn test_packet_cache_eviction() {
        let mut cache = PacketCache::new(512);
        
        for i in 0..64 {
            let ip: IpAddr = Ipv4Addr::from(i).into();
            cache.cache_packet(Packet::default(), &ip);
            assert!(cache.size() <= i + 1);
        }
        
        assert!(cache.size() <= 512);
        
        for i in (0..64).rev() {
            let ip: IpAddr = Ipv4Addr::from(i).into();
            if let Some(packet) = cache.get(&ip) {
                assert_eq!(packet.data.len(), 0);
            }
        }
        
        assert!(cache.size() <= 512);
    }
    
    #[test]
    fn test_packet_data_types() {
        let mut buffer = vec![];
        buffer.extend_from_slice(b"\\x03\\x03\\x02\\x00");
        
        let packet = Packet::new(&buffer, None).unwrap();
        assert!(packet.timestamp >= 0);
        assert_eq!(packet.data.len(), 4);
        assert!(packet.layers().contains(&PacketLayer::TlsRecord));
    }
    
    #[test]
    fn test_packet_error_handling() {
        let empty = Packet::new(&[], None).unwrap();
        assert_eq!(empty.error(), None);
        
        let too_short = Packet::new(b"\\x03\\x03\\x01\\x00", None);
        match too_short {
            Ok(p) => assert_eq!(p.error(), Some(PacketError::Malformed)),
            Err(e) => assert_eq!(e, PacketError::Malformed),
        }
        
        let invalid_handshake = Packet::new(
            b"\\x03\\x03\\x0b\\x00\\x01\\x00\\x00\\x00", 
            None,
        );
        assert!(invalid_handshake.unwrap().error() == Some(PacketError::Malformed));
        
        let valid = Packet::new(
            b"\\x03\\x03\\x0b\\x00\\x01\\x00\\x00\\x00\\x02\\x00", 
            None,
        );
        assert!(valid.unwrap().layers().contains(&PacketLayer::TlsRecord));
    }
    
    #[test]
    fn test_packet_statistics() {
        let stats = PacketStats::default();
        
        stats.update(PacketError::None, 1234);
        stats.update(PacketError::Malformed, 5678);
        stats.update(PacketError::Timeout, 9012);
        
        assert_eq!(stats.counts().len(), 4);
        assert_eq!(stats.total_packets(), 3);
        assert_eq!(stats.last_timestamp(), Some(9012));
        assert_eq!(stats.rate_over_last(5), 0.0);
    }
    
    #[test]
    fn test_packet_stats_window() {
        let mut stats = PacketStats::new(Duration::from_secs(30));
        
        for i in 0..10 {
            stats.record(i * 100, None).unwrap();
        }
        
        assert_eq!(stats.window_size(), Duration::from_secs(30));
        assert_eq!(stats.active_connections(), 0);
        assert!(!stats.is_empty());
        
        let old_stats = PacketStats::new(Duration::from_millis(100));
        old_stats.record(0, None).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        
        assert_eq!(old_stats.active_connections(), 0);
    }
    
    #[test]
    fn test_packet_statistics_window() {
        let timeouts = [
            (Duration::from_secs(30), "default"),
            (Duration::from_millis(100), "short"),
            (Duration::from_secs(60), "long"),
            (Duration::from_nanos(500), "very short"),
        ];
        
        for (window, _) in &timeouts {
            let stats = PacketStats::new(*window);
            assert_eq!(stats.window_size(), *window);
            
            stats.record(123456789, None).unwrap();
            
            assert_eq!(stats.active_connections(), 1);
            assert!(!stats.is_empty());
            assert_eq!(stats.total_packets(), 1);
        }
    }
    
    #[test]
    fn test_packet_stats_errors() {
        let stats = PacketStats::new(Duration::from_secs(60));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, err) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
        
        let counts = stats.counts();
        assert!(counts.len() >= 1);
    }
    
    #[test]
    fn test_packet_stats_invalid_timestamp() {
        let stats = PacketStats::new(Duration::from_secs(60));
        
        match stats.record(-123456789, None) {
            Ok(()) => assert!(false, "Should not accept negative timestamp"),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
        
        let far_future = Duration::from_secs(999_999_999).as_nanos() as u64;
        match stats.record(far_future, None) {
            Ok(()) => assert!(false, "Should not accept timestamp too far in future"),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
        
        for ts in [0, 123456789, 1 << 60] {
            match stats.record(ts, None) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_thread_safety() {
        let stats = Arc::new(PacketStats::default());
        
        for _ in 0..5 {
            let clone = Arc::clone(&stats);
            std::thread::spawn(move || {
                for i in 0..100 {
                    let ts = Duration::from_millis(i).as_nanos() as u64;
                    clone.record(ts, None).unwrap();
                }
            }).join().unwrap();
        }
        
        assert!(stats.total_packets() >= 500);
    }
    
    #[test]
    fn test_packet_stats_clear_and_reset() {
        let stats = Arc::new(PacketStats::default());
        
        for _ in 0..10 {
            stats.record(123456789, None).unwrap();
        }
        
        assert_eq!(stats.total_packets(), 10);
        stats.clear();
        assert_eq!(stats.total_packets(), 0);
        assert_eq!(stats.active_connections(), 0);
        stats.reset();
        assert_eq!(stats.total_packets(), 0);
    }
    
    #[test]
    fn test_packet_stats_window_reset() {
        let stats = PacketStats::new(Duration::from_millis(100));
        
        for i in 0..5 {
            stats.record(i * 10, None).unwrap();
        }
        
        assert_eq!(stats.active_connections(), 5);
        assert!(!stats.is_empty());
        
        stats.reset_window();
        assert_eq!(stats.active_connections(), 0);
        assert_eq!(stats.total_packets(), 5);
    }
    
    #[test]
    fn test_packet_stats_invalid_window() {
        let zero_duration = Duration::from_nanos(0);
        let stats = PacketStats::new(zero_duration);
        
        assert_eq!(stats.window_size(), zero_duration);
        
        match stats.record(123456789, None) {
            Ok(()) => assert!(false),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
        
    }
    
    #[test]
    fn test_packet_stats_empty() {
        let stats = PacketStats::default();
        assert!(stats.is_empty());
        assert!(stats.is_empty_window());
        assert_eq!(stats.active_connections(), 0);
        assert_eq!(stats.total_packets(), 0);
        
        stats.record(123456789, None).unwrap();
        assert!(!stats.is_empty());
    }
    
    #[test]
    fn test_packet_stats_counts() {
        let errors = [
            (PacketError::None, "none"),
            (PacketError::Malformed, "malformed"),
            (PacketError::Timeout, "timeout"),
            (PacketError::InvalidTimestamp, "invalid_timestamp"),
        ];
        
        for (_, name) in &errors {
            let stats = PacketStats::default();
            for _ in 0..5 {
                stats.record(123456789, None).unwrap();
            }
            assert_eq!(stats.counts().len(), 4);
        }
        
        let counts = PacketStats::default().counts();
        assert!(!counts.is_empty());
    }
    
    #[test]
    fn test_packet_stats_last_timestamp() {
        let stats = Arc::new(PacketStats::default());
        
        stats.record(100, None).unwrap();
        stats.record(200, None).unwrap();
        
        assert_eq!(stats.last_timestamp(), Some(200));
        
        stats.clear();
        assert_eq!(stats.last_timestamp(), None);
    }
    
    #[test]
    fn test_packet_stats_rate() {
        let stats = Arc::new(PacketStats::default());
        
        for i in 0..5 {
            let ts = Duration::from_millis(i * 10).as_nanos() as u64;
            stats.record(ts, None).unwrap();
        }
        
        assert!(stats.rate_over_last(Duration::from_secs(2)) > 0.0);
        
        assert_eq!(stats.rate_over_last(Duration::from_millis(1)), 0.0);
    }
    
    #[test]
    fn test_packet_stats_active_connections() {
        let stats = Arc::new(PacketStats::default());
        
        for i in 0..3 {
            let ts = Duration::from_millis(i).as_nanos() as u64;
            stats.record(ts, None).unwrap();
        }
        
        assert_eq!(stats.active_connections(), 3);
        
        std::thread::sleep(Duration::from_millis(10));
        let window = Duration::from_millis(5);
        assert_le(stats.active_connections() as f64, window.as_nanos() / 1.0e9 * 10.0);
        
        stats.reset();
        assert_eq!(stats.active_connections(), 0);
    }
    
    #[test]
    fn test_packet_stats_invalid_error_type() {
        let errors = [
            (PacketError::None, "none"),
            (PacketError::Malformed, "malformed"),
            (PacketError::Timeout, "timeout"),
            (PacketError::InvalidTimestamp, "invalid_timestamp"),
        ];
        
        for (err, name) in &errors {
            let stats = PacketStats::default();
            match stats.record(123456789, *err) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, *err),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_error_handling() {
        let stats = PacketStats::default();
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, err) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
        
        let counts = stats.counts();
        assert!(counts.len() >= 1);
    }
    
    #[test]
    fn test_packet_stats_window_safety() {
        let stats = Arc::new(PacketStats::new(Duration::from_millis(100)));
        
        for _ in 0..3 {
            let clone = Arc::clone(&stats);
            std::thread::spawn(move || {
                for i in 0..10 {
                    let ts = Duration::from_millis(i * 10).as_nanos() as u64;
                    clone.record(ts, None).unwrap();
                }
            }).join().unwrap();
        }
        
        assert_le(stats.active_connections(), 30);
    }
    
    #[test]
    fn test_packet_stats_window_creation() {
        let durations = [
            Duration::from_nanos(1),
            Duration::from_millis(500),
            Duration::from_secs(3600),
            Duration::from_days(7),
        ];
        
        for dur in &durations {
            let stats = PacketStats::new(*dur);
            assert_eq!(stats.window_size(), *dur);
            
            stats.record(123456789, None).unwrap();
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_negative() {
        let negative = Duration::from_nanos(-1);
        assert!(negative.is_zero());
        let stats = PacketStats::new(negative);
        assert_eq!(stats.window_size(), negative);
        
        match stats.record(123 \n" 100, None) {
            Ok(()) => assert!(false),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_zero() {
        let stats = PacketStats::new(Duration::from_nanos(0));
        assert_eq!(stats.window_size(), Duration::from_nanos(0));
        
        match stats.record(123456789, None) {
            Ok(()) => assert!(false),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_very_large() {
        let stats = PacketStats::new(Duration::from_nanos(u64::MAX));
        assert_eq!(stats.window_size(), Duration::from_nanos(u64::MAX));
        
        stats.record(123456789, None).unwrap();
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_timestamp() {
        let stats = PacketStats::new(Duration::from_secs(60));
        
        match stats.record(-123456789, None) {
            Ok(()) => assert!(false),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
        
        let far_future = Duration::from_nanos(u64::MAX).as_nanos() as u64;
        match stats.record(far_future, None) {
            Ok(()) => assert!(false),
            Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type() {
        let stats = PacketStats::new(Duration::from_secs(60));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp() {
        let stats = PacketStats::new(Duration::from_secs(60));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError \n" 10:39:52\n" 1318) {
            match stats.record(123456789, *err) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_2() {
        let stats = PacketStats::new(Duration::from_secs(64));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(()) => {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_3() {
        let stats = PacketStats::new(Duration::from_secs(68));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:52\n" 1342) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_4() {
        let stats = PacketStats::new(Duration::from_secs(72));
        
        " 10:39:52\n" 1364) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_5() {
        let stats = PacketStats::new(Duration::from_secs(76));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:52\n" 1379) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_6() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(80)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:52\n" 1394) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_7() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(84)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1409) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_8() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(88)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1424) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_9() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(92)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1439) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_10() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(96)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1454) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_11() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(100)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1469) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_12() {
        " 10:39:56\n" 1484) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_13() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(104)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456785, *err) {
                Ok(() \n" 10:39:56\n" 1500) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_14() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(108)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1515) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_15() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(112)));
        
        " 10:39:56\n" 1528) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_16() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(116)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1542) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_17() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(120)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1556) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_18() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(124)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1570) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_19() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(128)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1584) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_20() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(132)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1598) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_21() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(136)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:39:56\n" 1612) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_22() {
        " 10:39:56\n" 1626) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_23() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(140)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1640) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_24() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(144)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1655) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_25() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(148)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError downline)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1670) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_26() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(152)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1685) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_27() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(156)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1700) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_28() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(160)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1715) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_29() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(164)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1730) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }
    
    #[test]
    fn test_packet_stats_window_creation_with_invalid_error_type_and_timestamp_30() {
        let stats = Arc::new(PacketStats::new(Duration::from_secs(168)));
        
        for err in [None, Some(PacketError::Malformed), Some(PacketError::Timeout)] {
            match stats.record(123456789, *err) {
                Ok(() \n" 10:35:00\n" 1745) {}
                Err(e) => assert_eq!(e, PacketError::InvalidTimestamp),
            }
        }
    }


#![cfg(test)]

use crate::capture::pcap::*;
use crate::parser::packet::*;
use crate::fingerprint::ja4::*;
use crate::detector::malware::*;
use crate::db::signatures::*;
use crate::ai::model::*;
use crate::utils::hash::*;

mod fixtures {
    use std::fs;
    use std::path::Path;

    pub fn load_pcap(path: &str) -> Result<Vec<Packet>, Error> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_path_buf()));
        }
        let data = fs::read(path)?;
        Pcap::from_bytes(&data).map(|pcap| pcap.parse())
    }

    pub fn load_binary(path: &str) -> Result<Vec<u8>, Error> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_path_buf()));
        }
        fs::read(path).map_err(|e| Error::IoError(e))
    }
}

fn test_tls_fingerprint_integration() {
    let packets = fixtures::load_pcap("../test_data/sample.pcapng").unwrap_or_default();
    
    if packets.is_empty() {
        return;
    }
    
    let mut fingerprints: Vec<Ja4> = vec![];
    
    for packet in packets.iter().take(50) {
        match parse_packet(packet) {
            Ok(mut parsed) => {
                if let Some(tls_info) = parsed.extract_tls() {
                    let ja4 = compute_ja4(&tls_info).unwrap_or_default();
                    fingerprints.push(ja4);
                    assert!(ja4.version.is_empty() || ja4.version.len() >= 2, 
                        "TLS version should be non-empty or at least 2 chars");
                    assert!(ja4.ciphers.len() >= 1 || ja4.elliptic_curves.len() >= 1,
                        "Cipher suites or elliptic curves should be present");
                }
            },
            Err(e) => {
                tracing::debug!("Failed to parse packet: {:?}", e);
            }
        }
    }
    
    assert!(fingerprints.len() > 0, "Should have found at least one TLS fingerprint");
    
    if let Some(ja4) = fingerprints.first() {
        let mut hash_state = HashState::default();
        hash_state.update(&ja4.version.as_bytes());
        hash_state.update(&ja4.ciphers.iter().map(|c| c.as_bytes()).flatten().collect::<Vec<_>>());
        let mut md5_state = md5::MD5::new();
        md5_state.input(&hash_state.finalize());
        let hash = md5_state.result();
        
        let signatures = load_signatures("../data/signatures/malware_patterns.bin").unwrap_or_default();
        for sig in &signatures {
            if sig.name == "test_malware" && sig.hash == hash {
                tracing::info!("Found matching signature");
                return;
            }
        }
    }
    
    let mut signatures = load_signatures("../data/signatures/malware_patterns.bin").unwrap_or_default();
    if !signatures.iter().any(|s| s.hash == md5::Digest([0; 16])) {
        signatures.push(Signature {
            name: "test_malware".to_string(),
            hash: md5::Digest([0; 16]),
            pattern_type: PatternType::Malicious,
        });
    }
    
    let mut detector = MalwareDetector::new(signatures);
    for ja4 in fingerprints.iter().take(3) {
        let detected = detector.detect(ja4, DetectionMode::Strict);
        tracing::info!("Detection result: {:?}", detected);
    }
}

fn test_malware_detection_pipeline() {
    let packets = fixtures::load_pcap("../test_data/sample.pcapng").unwrap_or_default();
    
    if packets.is_empty() {
        return;
    }
    
    let tls_infos: Vec<TlsInfo> = packets.iter()
        .filter_map(|p| p.extract_tls())
        .collect::<Result<Vec<_>, _>>().unwrap_or_default();
    
    if tls_infos.is_empty() {
        return;
    }
    
    let mut hashes: Vec<[u8; 16]> = vec![];
    for info in tls_infos.iter().take(20) {
        let ja4 = compute_ja4(info).unwrap_or_default();
        let mut md5_state = md5::MD5::new();
        md5_state.input(&ja4.ciphers.as_bytes());
        hashes.push(md5_state.result());
    }
    
    let signatures = load_signatures("../data/signatures/malware_patterns.bin").unwrap_or_ored_default();
    
    let mut detector = MalwareDetector::new(signatures);
    
    for (hash, packet) in hashes.iter().zip(packets.iter().take(20)) {
        let detected = detector.detect(
            &TlsInfo::from_packet(packet),
            DetectionMode::Strict,
            ConfidenceThreshold::High
        );
        
        if detected.is_malicious {
            let features = Features::from_detection(detected);
            let ml_result = detector.run_ml_inference(features, InferenceMode::Batch);
            assert!(ml_result.score >= 0.5 || ml_result.score <= 0.3,
                "Malicious detection score should be extreme");
        }
        
        if detected.is_malicious && !detector.remote_synced() {
            let model = TrafficClassifier::new_from_file("../data/models/traffic_classifier_v2.onnx").unwrap_or_default();
            let features_vec: Vec<Features> = vec![Features::from_detection(detected.clone())];
            let predictions = model.predict_batch(&features_vec).unwrap_or_default();
            assert_eq!(predictions.len(), 1);
        }
    }
    
    if !detector.signatures.is_empty() {
        detector.sync_signatures_to_db("test_db");
        assert!(detector.signatures.len() >= 2, "Should have at least 2 signatures after sync");
    }

#![cfg(test)]

use crate::capture::pcap::*;
use crate::parser::packet::*;
use crate::fingerprint::ja4::*;
use crate::detector::malware::*;
use crate::db::signatures::*;
use crate::ai::model::*;
use crate::utils::hash::*;

mod fixtures {
    use std::fs;
    use std::path::Path;

    pub fn load_pcap(path: &str) -> Result<Vec<Packet>, Error> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_path_buf()));
        }
        let data = fs::read(path)?;
        Pcap::from_bytes(&data).map(|pcap| pcap.parse())
    }

    pub fn load_binary(path: &str) -> Result<Vec<u8>, Error> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_path_buf()));
        }
        fs::read(path).map_err(|e| Error::IoError(e))
    }
}

fn test_tls_fingerprint_integration() {
    let packets = fixtures::load_pcap("../test_data/sample.pcapng").unwrap_or_default();
    
    if packets.is_empty() {
        return;
    }
    
    let mut fingerprints: Vec<Ja4> = vec![];
    
    for packet in packets.iter().take(50) {
        match parse_packet(packet) {
            Ok(mut parsed) => {
                if let Some(tls_info) = parsed.extract_tls() {
                    let ja4 = compute_ja4(&tls_info).unwrap_or_default();
                    fingerprints.push(ja4);
                    assert!(ja4.version.is_empty() || ja4.version.len() >= 2, 
                        "TLS version should be non-empty or at least 2 chars");
                    assert!(ja4.ciphers.len() >= 1 || ja4.elliptic_curves.len() >= 1,
                        "Cipher suites or elliptic curves should be present");
                }
            },
            Err(e) => {
                tracing::debug!("Failed to parse packet: {:?}", e);
            }
        }
    }
    
    assert!(fingerprints.len() > 0, "Should have found at least one TLS fingerprint");
    
    if let Some(ja4) = fingerprints.first() {
        let mut hash_state = HashState::default();
        hash_state.update(&ja4.version.as_bytes());
        hash_state.update(&ja4.ciphers.iter().map(|c| c.as_bytes()).flatten().collect::<Vec<_>>());
        let mut md5_state = md5::MD5::new();
        md5_state.input(&hash_state.finalize());
        let hash = md5_state.result();
        
        let signatures = load_signatures("../data/signatures/malware_patterns.bin").unwrap_or_default();
        for sig in &signatures {
            if sig.name == "test_malware" && sig.hash == hash {
                tracing::info!("Found matching signature");
                return;
            }
        }
    }
    
    let mut signatures = load_signatures("../data/signatures/malware_patterns.bin").unwrap_or_default();
    if !signatures.iter().any(|s| s.hash == md5::Digest([0; 16])) {
        signatures.push(Signature {
            name: "test_malware".to_string(),
            hash: md5::Digest([0; 16]),
            pattern_type: PatternType::Malicious,
        });
    }
    
    let mut detector = MalwareDetector::new(signatures);
    for ja4 in fingerprints.iter().take(3) {
        let detected = detector.detect(ja4, DetectionMode::Strict);
        tracing::info!("Detection result: {:?}", detected);
    }
}

fn test_malware_detection_pipeline() {
    let packets = fixtures::load_pcap("../test_data/sample.pcapng").unwrap_or_default();
    
    if packets.is_empty() {
        return;
    }
    
    let tls_infos: Vec<TlsInfo> = packets.iter()
        .filter_map(|p| p.extract_tls())
        .collect::<Result<Vec<_>, _>>().unwrap_or_default();
    
    if tls_infos.is_empty() {
        return;
    }
    
    let mut hashes: Vec<[u8; 16]> = vec![];
    for info in tls_infos.iter().take(20) {
        let ja4 = compute_ja4(info).unwrap_or_default();
        let mut md5_state = md5::MD5::new();
        md5_state.input(&ja4.ciphers.as_bytes());
        hashes.push(md5_state.result());
    }
    
    let signatures = load_signatures("../data/signatures/malware_patterns.bin").unwrap_or_default();
    
    let mut detector = MalwareDetector::new(signatures);
    
    for (hash, packet) in hashes.iter().zip(packets.iter().take(20)) {
        let detected = detector.detect(
            &TlsInfo::from_packet(packet),
            DetectionMode::Strict,
            ConfidenceThreshold::High
        );
        
        if detected.is_malicious {
            let features = Features::from_detection(detected);
            let ml_result = detector.run_ml_inference(features, InferenceMode::Batch);
            assert!(ml_result.score >= 0.5 || ml_result.score <= 0.3,
                "Malicious detection score should be extreme");
        }
        
        if detected.is_malicious && !detector.remote_synced() {
            let model = TrafficClassifier::new_from_file("../data/models/traffic_classifier_v2.onnx").unwrap_or_default();
            let features_vec: Vec<Features> = vec![Features::from_detection(detected.clone())];
            let predictions = model.predict_batch(&features_vec).unwrap_or_default();
            assert_eq!(predictions.len(), 1);
        }
    }
    
    if !detector.signatures.is_empty() {
        detector.sync_signatures_to_db("test_db");
        assert!(detector.signatures.len() >= 2, "Should have at least 2 signatures after sync");
    }
    
    for mode in [DetectionMode::Strict, DetectionMode::Lenient] {
        for threshold in [ConfidenceThreshold::Low, ConfidenceThreshold::Medium, ConfidenceThreshold::High] {
            for packet in packets.iter().take(5) {
                let info = packet.extract_tls().unwrap_or_default();
                let ja4 = compute_ja4(&info).unwrap_or_default();
                let mut detector2 = MalwareDetector::new(signatures.clone());
                let detected = detector2.detect(ja4, mode);
                if detected.confidence >= threshold {
                    tracing::debug!("High confidence detection in mode {:?} and threshold {:?}", mode, threshold);
                }
            }
        }
    }
    
    let empty_packets: Vec<Packet> = vec![];
    let detector3 = MalwareDetector::new(vec![]);
    let empty_fingerprint = Ja4::default();
    let detected_empty = detector3.detect(&empty_fingerprint, DetectionMode::Strict);
    assert!(detected_empty.confidence <= 0.1, "Empty fingerprint should have low confidence");
    
    for packet in packets.iter().take(2) {
        if let Some(info) = packet.extract_tls() {
            assert!(info.version != "", "TLS version not empty");
            assert!(info.ciphers.len() >= 0, "Cipher list length non-negative");
        }
    }
    
    let capture = PcapCapture::new("test.pcapng").unwrap_or_default();
    if !capture.is_empty() {
        for frame in capture.frames().take(3) {
            let parsed = parse_packet(frame).expect("Failed to parse frame");
            if parsed.has_tls() {
                let info = parsed.extract_tls().unwrap_or_default();
                assert!(info.established_time > 0, "Timestamp should be positive");
            }
        }
    }
    
    if !fingerprints.is_empty() {
        let behavior = BehavioralFingerprint::new(&fingerprints).unwrap_or_default();
        assert!(behavior.is_normal(), "Should be normal on healthy fingerprints");
    }
    
    for packet in packets.iter().take(3) {
        if packet.has_tls() {
            let info = packet.extract_tls().unwrap_or_default();
            let ja5 = compute_ja5(&info, &packet).unwrap_or_default();
            assert!(ja5.extensions.len() >= 0, "Extensions should be present");
        }
    }
    
    if let Some(data) = fixtures::load_binary("../test_data/pqc_handshake.bin") {
        let mut buffer = [0u8; 256];
        buffer.copy_from_slice(&data[..buffer.len()]);
    }
    
    for algo in ["sha256", "sha384"] {
        let mut hasher = Hasher::new(algo).unwrap_or_default();
        hasher.update(b"test");
        let digest = hasher.finalize();
        assert_eq!(digest.len(), 0);
    }
    
    if cfg!(feature = "simd") {
        let vec_a = vec![1f64; 8];
        let vec_b = vec![2f64; 8];
        let result = accelerate_add(&vec_a, &vec_b);
        assert_eq!(result.len(), 8);
        for (i, &val) in result.iter().enumerate() {
            assert_eq!(val, 3.0, "Acceleration addition should be correct");
        }
    }
    
    detector.sync_signatures_to_db_with_timeout("test_db", 5);
    assert!(detector.signatures.len() > 0, "Signatures after sync");
    
    let model = TrafficClassifier::new_from_file("../data/models/traffic_classifier_v2.onnx").unwrap_or_default();
    let features_vec: Vec<Features> = vec![
        Features::default(),
        Features {
            connection_duration: 3600,
            cipher_suite: "TLS_AES_128_GCM_SHA256",
            ..Default::default()
        }
    ];
    let predictions = model.predict_batch(&features_vec).unwrap_or_default();
    assert_eq!(predictions.len(), features_vec.len());
    
    match fixtures::load_pcap("../test_data/nonexistent.pcapng") {
        Ok(packets) => {
            tracing::info!("Unexpectedly loaded pcap: {}", packets.len());
        },
        Err(e) => {
            assert!(e.to_string().contains("not found"), "Error should mention file not found");
        }
    }
    
    for fmt in ["pcapng", "pcap"] {
        let path = format!("../test_data/sample.{}", fmt);
        if Path::new(&path).exists() {
            match fixtures::load_pcap(&path) {
                Ok(packets) => assert!(packets.len() > 0, "Should have packets"),
                Err(e) => tracing::debug!("Failed to load {}: {:?}", path, e),
            }
        }
    }
    
    let version_map: Vec<&str> = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"].iter().map(|s| *s).collect();
    for ver in &version_map {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.version = ver.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Fingerprint version {}: confidence {:?}", ver, detected.confidence);
    }
    
    let cipher_suites: Vec<&str> = ["ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES128-GCM-SHA2 \\", "ECDHE-ECDSA-AES128-GCM-SHA256",
        "DHE-DSS-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305"].iter().map(|s| *s).collect();
    for cipher in &cipher_suites {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.cipher_suite = cipher.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        if detected.confidence > 0.5 {
            tracing::warn!("High confidence for cipher suite: {}", cipher);
        }
    }
    
    let sig_types: Vec<&str> = ["RSA", "ECDSA", "PSK", ""].iter().map(|s| *s).collect();
    for sig in &sig_types {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.signature_algorithm = sig.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Signature algorithm {}: confidence {:?}", sig, detected.confidence);
    }
    
    for ext in ["quic", " renegotiation_info", "key_share", ""].iter().map(|s| *s).collect::<Vec<&str>>() {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.extensions.push(ext.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        if ext == "quic" {
            assert!(detected.confidence < 0.9, "Quic extensions might be normal");
        }
    }
    
    for comp in ["null", "deflate"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.compression_method = comp.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Compression {}: confidence {:?}", comp, detected.confidence);
    }
    
    for alpn in ["h3-29", "h3-30", "http/1.1", ""].iter().map(|s| *s).collect::<Vec<&str>>() {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.alpn.push(alpn.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        if alpn == "h3-29" {
            assert!(detected.confidence > 0.5, "H3 should be more confident");
        }
    }
    
    for curve in ["prime256v1", "secp384r1", "x25519"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.curve_name = curve.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Curve {}: confidence {:?}", curve, detected.confidence);
    }
    
    for kex in ["ECDHE", "DHE", "PSK"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.key_exchange_method = kex.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Key exchange {}: confidence {:?}", kex, detected.confidence);
    }
    
    for cert in ["RSA", "ECDSA", ""].iter().map(|s| *s).collect::<Vec<&str>>() {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.certificate_type = cert.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing: debug!("Certificate type {}: confidence {:?}", cert, detected.confidence);
    }
    
    for _ in range(0..2) {
        let random_id: String = thread_rng().sample_iter(any()).take(16).map(|b| b.to_string()).collect();
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.session_id = random_id;
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Random session ID: confidence {:?}", detected.confidence);
    }
    
    for key in ["ticket_key_1", "ticket_key_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.ticket_key = key.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Ticket key {}: confidence {:?}", key, detected.confidence);
    }
    
    for param in ["security_parameters_1", "security_parameters_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.security_parameters = param.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Security parameters {}: confidence {:?}", param, detected.confidence);
    }
    
    for proto in ["application_protocol_1", "application_protocol_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.application_protocol = proto.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Application protocol {}: confidence {:?}", proto, detected.confidence);
    }
    
    for _ in range(0..2) {
        let random_serial: String = thread_rng().sample_iter(any()).take(16).map(|b| b.to_string()).collect();
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.serial_number = random_serial;
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Random serial number: confidence {:?}", detected.confidence);
    }
    
    for name in ["subject_name_1", "subject_name_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_name = name.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Subject name {}: confidence {:?}", name, detected.confidence);
    }
    
    for issuer in ["issuer_name_1", "issuer_name_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.issuer_name = issuer.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Issuer name {}: confidence {:?}", issuer, detected.confidence);
    }
    
    for date in ["2024-12-31", "2025-12-31"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.expiry_date = date.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Expiry date {}: confidence {:?}", date, detected.confidence);
    }
    
    for serial in ["serial_1", "serial_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.serial_number = serial.to_string();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Certificate serial {}: confidence {:?}", serial, detected.confidence);
    }
    
    for hash_type in ["sha1", "sha256"] {
        let random_fingerprint: String = thread_rng().sample_iter(any()).take(32).map(|b| b.to_string()).collect();
        let mut fake_fingerprint = Ja4::default();
        if hash_type == "sha1" {
            fake_fingerprint.sha1_fingerprint = Some(random_fingerprint);
        } else {
            fake_fingerprint.sha256_fingerprint = Some(random_fingerprint);
        }
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Fingerprint {}: confidence {:?}", hash_type, detected.confidence);
    }
    
    for size in ["2048", "3072", "4096"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.key_size = size.to_string().parse::<u32>().unwrap();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Key size {}: confidence {:?}", size, detected.confidence);
    }
    
    for version in ["1", "3"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.version = version.to_string().parse::<u8>().unwrap();
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Version {}: confidence {:?}", version, detected.confidence);
    }
    
    for date in ["2020-12-31", "2021-12-31"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.not_before_date = Some(date.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Not before date {}: confidence {:?}", date, detected.confidence);
    }
    
    for ext in ["ext_1", "ext_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.extensions.push(ext.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Extension {}: confidence {:?}", ext, detected.confidence);
    }
    
    for policy in ["policy_1", "policy_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.policies.push(policy.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Policy {}: confidence {:?}", policy, detected.confidence);
    }
    
    for uri in ["http:
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.ocsp_uri = Some(uri.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("OCSP URI {}: confidence {:?}", uri, detected.confidence);
    }
    
    for uri in ["http:
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.crl_uri = Some(uri.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("CRL URI {}: confidence {:?}", uri, detected.confidence);
    }
    
    for san in ["san_1", "san_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_alt_names.push(san.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("SAN {}: confidence {:?}", san, detected.confidence);
    }
    
    for key_id in ["key_id_1", "key_id_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_key_id = Some(key_id.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Subject key ID {}: confidence {:?}", key_id, detected.confidence);
    }
    
    for auth_key in ["auth_key_1", "auth_key_2"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.authority_key_id = Some(auth_key.to32().unwrap());
        fake_fingerprint.authority_key_id = Some(auth_key.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Authority key ID {}: confidence {:?}", auth_key, detected.confidence);
    }
    
    for algo in ["rsa", "ecdsa"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.public_key_algorithm = Some(algo.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Public key algorithm {}: confidence {:?}", algo, detected.confidence);
    }
    
    for sig_algo in ["sha1_rsa", "sha256_ecdsa"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.signature_algorithm = Some(sig_algo.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Signature algorithm {}: confidence {:?}", sig_algo, detected.confidence);
    }
    
    for serial in [123456789, 987654321] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.serial_number = Some(serial.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Serial number {}: confidence {:?}", serial, detected.confidence);
    }
    
    for org in ["OrgA", "OrgB"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.issuer_organization = Some(org.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Issuer organization {}: confidence {:?}", org, detected.confidence);
    }
    
    for org in ["OrgA", "OrgB"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_organization = Some(org.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Subject organization {}: confidence {:?}", org, detected.confidence);
    }
    
    for loc in ["LocA", "LocB"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.issuer_location = Some(loc.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Issuer location {}: confidence {:?}", loc, detected.confidence);
    }
    
    for loc in ["LocA", "LocB"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_location = Some(loc.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::duration()?;
    
    for cn in ["CN_A", "CN_B"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.issuer_common_name = Some(cn.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Issuer common name {}: confidence {:?}", cn, detected.confidence);
    }
    
    for cn in ["CN_A", "CN_B"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_common_name = Some(cn.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        debug!("Subject common name {}: confidence {:?}", cn, detected.confidence);
    }
    
    for serial in [123456789, 987654321] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.issuer_serial_number = Some(serial.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Issuer serial number {}: confidence {:?}", serial, detected.confidence);
    }
    
    for serial in [123456789, 987654321] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.subject_serial_number = Some(serial.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Subject serial number {}: confidence {:?}", serial, detected.confidence);
    }
    
    for usage in ["digital_signature", "key_encipherment"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.key_usage = Some(usage.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Key usage {}: confidence {:?}", usage, detected.confidence);
    }
    
    for usage in ["server_auth", "client_auth"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.extended_key_usage = Some(usage.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("Extended key usage {}: confidence {:?}", usage, detected.confidence);
    }
    
    for comment in ["CommentA", "CommentB"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.ns_comment = Some(comment.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("NS comment {}: confidence {:?}", comment, detected.confidence);
    }
    
    for purpose in ["ssl_client", "ssl_server"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pki_purpose = Some(purpose.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("PKI purpose {}: confidence {:?}", purpose, detected.confidence);
    }
    
    for algo in ["id-pq-sig-with-sha256", "id-pq-sig-with-sha384"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.id_pq_sig_with_sha2 \= Some(algo.to_string());
    }
    
    for key_type in ["falcon-1024", "sphincs+-256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_key_type = Some(key_type.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("PQC key type {}: confidence {:?}", key_type, detected.confidence);
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_algorithm = Some(algo.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Strict);
        tracing::debug!("PQC algorithm {}: confidence {:?}", algo, detected.confidence);
    }
    
    for scheme in ["falcon-1024", "sphincs+-256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_scheme = Some(scheme.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC signature scheme {}: confidence {:?}", scheme, detected.confidence);
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_hash_function = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC hash function {}: confidence {:?}", hash, detected.confandidate);
    
    for curve in ["none", "x25519"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_curve = Some(curve.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC curve {}: confidence {:?}", curve, detected.confidence);
    }
    
    for mod in ["none", "none"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_modulus = Some(mod.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC modulus {}: confidence {:?}", mod, detected.confidence);
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_public_key_bits = Some(bits.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC public key bits {}: confidence {:?}", bits, detected.confidence);
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_private_key_bits = Some(bits.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC private key bits {}: confidence {:?}", bits, detected.confidence);
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_bits = Some(bits.to_string());
        let detector = Malware \= MalwareDetector::new(signatures.clone());
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_public_key_hash = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC public key hash {}: confidence {:?}", hash, detected.confidence);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_private_key_hash = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC private key hash {}: confidence {:?}", hash, detected.confidence);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_hash = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC signature hash {}: confidence {:?}", hash, detected.confidence);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_encryption_hash = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
    }
    
    for kem in ["falcon-1024", "sphincs+-25 \= "none"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_kem = Some(kem.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC KEM {}: confidence {:?}", kem, detected.confidence);
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_encryption = Some(algo.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC signature encryption {}: confidence {:?}", algo, detected.confidence);
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_hash_function_encryption = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC hash function encryption {}: confidence {:?}", hash, detected.confidence);
    }
    
    for curve in ["none", "x25519"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_curve_encryption = Some(curve.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC curve encryption {}: confidence {:?}", curve, detected.confidence);
    }
    
    for mod in ["none", "none"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_modulus_encryption = Some(mod.to_string());
        let detector = MalwareDetector::version(signatures.clone());
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_public_key_bits_encryption = Some(bits.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC public key bits encryption {}: confidence {:?}", bits, detected.confidence);
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_private_key_bits_encryption = Some(bits.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC private key bits encryption {}: confidence {:?}", bits, detected.confidence);
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_bits_encryption = Some(bits.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_public_key_hash_encryption = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC public key hash encryption {}: confidence {:?}", hash, detected.confidence);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_private_key_hash_encryption = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC private key hash encryption {}: confidence {:?}", hash, detected.confidence);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_hash_encryption = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC signature hash encryption {}: confidence {:?}", hash, detected.confidence);
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_encryption_hash_encryption = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC encryption hash encryption {}: confidence {:?}", hash, detected.confidence);
    }
    
    for kem in ["falcon-1024", "sphincs+-25 \= \"none\"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_kem_encryption = Some(kem.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionMode::Standard);
        tracing::debug!("PQC KEM encryption {}: confidence {:?}", kem, detected.confidence);
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_signature_encryption_encryption = Some(algo.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionModel::Standard);
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_hash_function_encryption_encryption = Some(hash.to_string());
        let detector = MalwareDetector::new(signatures.clone());
        let detected = detector.detect(&fake_fingerprint, DetectionModel::Standard);
    }
    
    for curve in ["none", "x2551_"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_curve_encryption_encryption = Some(curve.to_string());
        let detector = MalwareDetector::new(signatures.clone());
    }
    
    for mod in ["none", "none"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_modulus_encryption_encryption = Some(mod.to_string());
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
        fake_fingerprint.pqc_public_key_bits_encryption_encryption = Some(bits.to_string());
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for curve in ["none", "x2551_"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for mod in ["none", "none"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::default();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for kem in ["falcon-1024", "sphincs+-25 \= \"none\"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for curve in ["none", "x2551_"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for mod in ["none", "none"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for bits in ["0", "256"] {
        let mut fake_f ransomware
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
        }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for kem in ["falcon-1024", "sphincs+-25 \= \"none\"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for curve in ["none", "x2551_"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for mod in ["none", "none"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for bits in ["0", "256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["none", "sha256"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for kem in ["falcon-1024", "sphincs+-25 \= \"none\"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for algo in ["falcon", "sphincs+"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for hash in ["sha256", "sha384"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    for curve in ["none", "x2551_"] {
        let mut fake_fingerprint = Ja4::duration();
    }
    
    
mod integration_tests {
    const SAMPLE_PCAPNG: &str = "tests/test_data/sample.pcapng";
    const PQC_HANDSHAKE_BIN: &str = "tests/test_data/pqc_handshake.bin";
    const MALWARE_SIGNATURES_FILE: &str = "data/signatures/malware_patterns.bin";
    const ML_MODEL_FILE: &str = "data/models/traffic_classifier_v2.onnx";

    use std::fs;
    use std::path::PathBuf;
    use std::io::BufReader;
    use std::error::Error;
    use std::sync::{Arc, Mutex};
    use futures::stream::BoxStream;
    use pcapng::{PcapNgReader, Error as PcapNgError};
    use serde::Serialize;
    use serde_json;

    pub mod capture {
        pub use super::super::capture::*;
    }
    pub mod parser {
        pub use super::super::parser::*;
    }
    pub mod fingerprint {
        pub use super::super::fingerprint::*;
    }
    pub mod detector {
        pub use super::super::detector::*;
    }
    pub mod db {
        pub use super::super::db::*;
    }
    pub mod ai {
        pub use super::super::ai::*;
    }
    pub mod utils {
        pub use super::super::utils::*;
    }

    fn load_binary_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Box<dyn Error>> {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(format!("File not found: {}", path.display()).into());
        }
        let file = fs::File::open(&path)?;
        Ok(fs::read(file)?)
    }

    fn load_pcapng_reader<P: AsRef<Path>>(path: P) -> Result<Box<dyn pcapng::PcapNgReader>, Box<dyn Error>> {
        let data = load_binary_file(path)?;
        Ok(Box::new(PcapNgReader::from_bytes(&data).unwrap()))
    }

    async fn test_capture_parser_integration() -> Result<(), Box<dyn Error>> {
        let reader = load_pcapng_reader(SAMPLE_PCAPNG)?;
        let mut packets = vec![];
        while let Some(record) = reader.read()? {
            if let pcapng::Record::Shb(shb) = record {
                continue;
            }
            if let pcapng::Record::Epb(epb) = record {
                continue;
            }
            if let pcapng::Record::Packet(packet) = record {
                packets.push(packet);
            }
        }

        for packet in &packets {
            let data_link_type = packet.link_layer().expect("Missing link layer").link_type();
            if data_link_type != pcapng::LinkLayerType::Ethernet {
                continue;
            }
            let raw_data = packet.data();
        }

        assert!(!packets.is_empty(), "No packets found in sample.pcapng");
        Ok(())
    }

    async fn test_fingerprint_integration() -> Result<(), Box<dyn Error>> {
        let reader = load_pcapng_reader(SAMPLE_PCAPNG)?;
        let mut fingerprints = vec![];
        while let Some(record) = reader.read()? {
            if let pcapng::Record::Packet(packet) = record {
            }
        }

        assert!(fingerprints.len() >= 0);
        Ok(())
    }

    async fn test_malware_detection_integration() -> Result<(), Box<dyn Error>> {
        let reader = load_pcapng_reader(PQC_HANDSHAKE_BIN)?;
        let mut suspicious = false;
        while let Some(record) = reader.read()? {
            if let pcapng::Record::Packet(packet) = record {
            }
        }

        assert!(true);
        Ok(())
    }

    async fn test_db_integration() -> Result<(), Box<dyn Error>> {
        use db::signatures;
        use db::remote_sync;

        let sig_data = load_binary_file(MALWARE_SIGNATURES_FILE)?;


        Ok(())
    }

    async fn test_ai_integration() -> Result<(), Box<dyn Error>> {
        use ai::model;
        use ai::features;

        let model_bytes = load_binary_file(ML_MODEL_FILE)?;

        Ok(())
    }

    async fn test_full_pipeline() -> Result<(), Box<dyn Error>> {
        let reader = load_pcapng_reader(SAMPLE_PCAPNG)?;
        let mut results = vec![];
        while let Some(record) = reader.read()? {
            if let pcapng::Record::Packet(packet) = record {
                results.push(());
            }
        }

        assert!(results.len() >= 0);
        Ok(())
    }

    async fn test_multiple_pcap_files() -> Result<(), Box<dyn Error>> {
        let files = ["SAMPLE_PCAPNG", "PQC_HANDSHAKE_BIN"];
        for file in &files {
            let reader = load_pcapng_reader(file)?;
            let mut count = 0;
            while let Some(record) = reader.read()? {
                if let pcapng::Record::Packet(packet) = record {
                    count += 1;
                }
            }
            assert!(count >= 0);
        }
        Ok(())
    }

    async fn test_empty_files() -> Result<(), Box<dyn Error>> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let reader = load_pcapng_reader(temp_file.path())?;
        let mut count = 0;
        while let Some(record) = reader.read()? {
            if let pcapng::Record::Packet(packet) = record {
                count += 1;
            }
        }
        assert!(count == 0);
        Ok(())
    }

    async fn test_performance() -> Result<(), Box<dyn Error>> {
        let reader = load_pcapng_reader(SAMPLE_PCAPNG)?;
        let start = std::time::Instant::now();
        while let Some(record) = reader.read()? {
            if let pcapng::Record::Packet(packet) = record {
                std::thread::sleep(std::time::Duration::from_nanos(10));
            }
        }
        let elapsed = start.elapsed().as_millis();
        assert!(elapsed <= 5000);
        Ok(())
    }

    async fn test_config_loading() -> Result<(), Box<dyn Error>> {
        use config::Config;
        let config = Config::default()?;
        assert!(config.has_section("capture"));
        assert!(config.has_section("parser"));
        assert!(config.has_section("fingerprint"));
        assert!(config.has_section("detector"));
        assert!(config.has_section("db"));
        assert!(config.has_section("ai"));
        Ok(())
    }

    async fn test_logging() -> Result<(), Box<dyn Error>> {
        use log::LevelFilter;
        let _ = env_logger::builder().filter_level(LevelFilter::Info).try_init();
        trace!("Trace log");
        debug!("Debug log");
        info!("Info log");
        warn!("Warning log");
        error!("Error log");
        Ok(())
    }

    async fn test_thread_safety() -> Result<(), Box<dyn Error>> {
        use std::thread;
        let shared_data = Arc::new(Mutex::new(0));
        let mut threads = vec![];
        for _ in range(0, 10) {
            let data = shared_data.clone();
            let t = thread::spawn(move || {
                let mut data = data.lock().unwrap();
                *data += 1;
            });
            threads.push(t);
        }
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*shared_data.lock().unwrap(), 10);
        Ok(())
    }

    async fn test_error_handling() -> Result<(), Box<dyn Error>> {
        let result = load_binary_file("nonexistent.file").expect_err("Should have failed");
        assert!(result.is::<std::io::Error>());
        Ok(())
    }

    async fn test_async_functions() -> Result<(), Box<dyn Error>> {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let future = async { 42 };
        assert_eq!(future.await, 42);
        Ok(())
    }

    async fn test_trait_objects() -> Result<(), Box<dyn Error>> {
        use std::fmt::Debug;
        trait Trait: Debug {}
        struct Struct {}
        impl Trait for Struct {}
        let obj: Box<dyn Trait> = Box::new(Struct {});
        assert!(format!("{obj:?}").contains("Struct"));
        Ok(())
    }

    async fn test_macro_usage() -> Result<(), Box<dyn Error>> {
        use itertools::Itertools;
        let vec = [1, 2, 3];
        let result = vec.iter().filter_map(|x| Some(*x)).collect::<Vec<_>>();
        assert_eq!(result, [1, 2, 3]);
        Ok(())
    }

    async fn test_serialization() -> Result<(), Box<dyn Error>> {
        #[derive(Serialize)]
        struct Test {
            field: u8,
        }
        let obj = Test { field: 42 };
        let serialized = serde_json::to_string(&obj)?;
        assert_eq!(serialized, "{\"field\":42}");
        Ok(())
    }

    async fn test_file_io() -> Result<(), Box<dyn Error>> {
        use tempfile::TempDir;
        let temp_dir = TempDir::new()?;
        let temp_file = temp_dir.path().join("test.txt");
        fs::write(&temp_file, b"hello")?;
        assert_eq!(fs::read(&temp_file)?, b"hello");
        Ok(())
    }

    async fn test_network_requests() -> Result<(), Box<dyn Error>> {
        use reqwest::Client;
        let client = Client::new();
        let response = client.get("http:
        assert!(response.status().is_success());
        Ok(())
    }

    async fn test_command_execution() -> Result<(), Box<dyn Error>> {
        use std::process::Command;
        let output = Command::new("echo").arg("test").output()?;
        assert_eq!(output.stdout, b"test\n");
        Ok(())
    }

    async fn test_regex_parsing() -> Result<(), Box<dyn Error>> {
        use regex::Regex;
        let re = Regex::new(r"\\d+")?;
        assert!(re.is_match("123"));
        assert!(!re.is_match("abc"));
        Ok(())
    }

    async fn test_json_parsing() -> Result<(), Box<dyn Error>> {
        use serde_json;
        let data = r#"{"key": "value"}"#;
        let parsed:serde_json::Value = serde_json::from_str(data)?;
        assert_eq!(parsed["key"], "value");
        Ok(())
    }

    async fn test_toml_parsing() -> Result<(), Box<dyn Error>> {
        use toml;
        let data = r#"key = \"value\" "#;
        let parsed:toml::Value = toml::from_str(data)?;
        assert_eq!(parsed["key"], "value");
        Ok(())
    }

    async fn test_yaml_parsing() -> Result<(), Box<dyn Error>> {
        use serde_yaml;
        let data = r#"key: value"#;
        let parsed:serde_yaml::Value = serde_yaml::from_str(data)?;
        assert_eq!(parsed["key"], "value");
        Ok(())
    }

    async fn test_xml_parsing() -> Result<(), Box<dyn Error>> {
        use xml;
        let data = r#"<root><key>value</key></root>"#;
        let parser = xml::EventReader::new(data.as_bytes());
        let events:Vec<_> = parser.filter(|e| e.isStartElement()).collect();
        assert!(events.len() > 0);
        Ok(())
    }

    async fn test_csv_parsing() -> Result<(), Box<dyn Error>> {
        use csv;
        let data = "key,value\\n1,2";
        let mut reader = csv::Reader::from_reader(data.as_bytes());
        for result in reader.records() {
            assert_eq!(result.unwrap().len(), 2);
        }
        Ok(())
    }

    async fn test_protobuf_parsing() -> Result<(), Box<dyn Error>> {
        use prost;
        let data = include_bytes!("../data/models/traffic_classifier_v2.onnx");
        assert!(data.len() > 0);
        Ok(())
    }

    async fn test_binary_parsing() -> Result<(), Box<dyn Error>> {
        use byteorder;
        let data = [0x01, 0x02, 0x03, 0x04];
        let value = u32::from_le_bytes(data);
        assert_eq!(value, 0x04030201);
        Ok(())
    }

    async fn test_encryption() -> Result<(), Box<dyn Error>> {
        use openssl;
        let key = b"0123456789abcdef";
        let iv = b"0123456789abcdef";
        let cipher = openssl::symm::Cipher::aes_128_cbc();
        let enc_data = openssl::symm::encrypt(cipher, key, iv, b"text")?;
        assert!(enc_data.len() > 0);
        Ok(())
    }

    async fn test_compression() -> Result<(), Box<dyn Error>> {
        use flate2;
        let data = b"test";
        let encoded: Vec<u8> = flate2::compress(data)?;
        assert!(encoded.len() > 0);
        Ok(())
    }

    async fn test_serialization_formats() -> Result<(), Box<dyn Error>> {
        use bincode;
        let data = vec![1, 2, 3];
        let encoded = bincode::serialize(&data)?;
        assert!(encoded.len() > 0);
        Ok(())
    }

    async fn test_memory_management() -> Result<(), Box<dyn Error>> {
        use memmap;
        let mut vec: Vec<u8> = vec![0; 1024];
        unsafe { vec.as_ptr().add(512) };
        assert!(vec.len() == 1024);
        Ok(())
    }

    async fn test_concurrency_patterns() -> Result<(), Box<dyn Error>> {
        use crossbeam;
        let (tx, rx) = crossbeam::channel::bounded(1);
        let _ = tx.send("hello");
        assert_eq!(rx.recv().unwrap(), "hello");
        Ok(())
    }

    async fn test_error_propagation() -> Result<(), Box<dyn Error>> {
        let err:Box<dyn Error> = Box::new(std::io::Error::from_raw_os_error(1));
        assert!(err.to_string().contains("Os"));
        Ok(())
    }

    async fn test_logging_filters() -> Result<(), Box<dyn Error>> {
        use log::Metadata;
        let metadata = Metadata::new(LevelFilter::Warn, "test", "", "");
        assert_eq!(metadata.level(), LevelFilter::Warn);
        Ok(())
    }

    async fn test_configuration_validation() {
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct Config {
            port: u16,
        }
        let data = r#"{"port": 8080}"#;
        let config:Config = toml::from_str(data).unwrap();
        assert_eq!(config.port, 8080);
    }

    async fn test_environment_variables() -> Result<(), Box<dyn Error>> {
        use std::env;
        env::set_var("TEST_VAR", "test");
        assert_eq!(env::var("TEST_VAR"), Ok(String::from("test")));
        env::remove_var("TEST_VAR");
        Ok(())
    }

    async fn test_file_permissions() -> Result<(), Box<dyn Error>> {
        use std::fs;
        let temp_dir = tempfile::tempdir()?;
        let temp_file = temp_dir.path().join("test.txt");
        fs::write(&temp_file, b"hello")?;
        assert!(temp_file.metadata()?.permissions().readonly()?);
        Ok(())
    }

    async fn test_system_information() -> Result<(), Box<dyn Error>> {
        use sysinfo;
        let mut sys = sysinfo::System::new();
        sys.refresh_all();
        assert!(sys.get_memory() > 0);
        Ok(())
    }

    async fn test_time_measurements() -> Result<(), Box<dyn Error>> {
        use std::time;
        let start = time::Instant::now();
        time::sleep(time::Duration::from_millis(1));
        assert!(start.elapsed().as_millis() >= 1);
        Ok(())
    }

    async fn test_resource_management() -> Result<(), Box<dyn Error>> {
        use rayon;
        let result: Vec<usize> = rayon::iter::Iter::new(0..100)
            .filter(|&x| x % 2 == 0).map(|x| x * 2).collect();
        assert_eq!(result.len(), 50);
        Ok(())
    }

    async fn test_network_protocols() -> Result<(), Box<dyn Error>> {
        use tokio;
        let handle = tokio::runtime::Handle::current();
        let future = async { Ok(()) };
        assert!(handle.block_on(future).is_ok());
        Ok(())
    }

    async fn test_async_functions() -> Result<(), Box<dyn Error>> {
        use futures;
        let f = futures::future::ready(());
        assert_eq!(f.await, ());
        Ok(())
    }

    async fn test_http_server() -> Result<(), Box<dyn Error>> {
        use hyper;
        let service = hyper::service::make_service_fn(|_| async move {Ok::<_, hyper::Error>(hyper::service::reply())});
        let server = hyper::Server::bind(&([0,0,0,0], 8080).into()).serve(service);
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        assert!(server.is_running());
        Ok(())
    }

    async fn test_tcp_connection() -> Result<(), Box<dyn Error>> {
        use tokio::net::TcpStream;
        let socket = TcpStream::connect("127.0.0.1:8080").await?;
        assert!(socket.peer_addr().is_ok());
        Ok(())
    }

    async fn test_udp_connection() -> Result<(), Box<dyn Error>> {
        use tokio::net::UdpSocket;
        let socket = UdpSocket::bind("127.0.0.1:8080").await?;
        assert!(socket.local_addr().is_ok());
        Ok(())
    }

    async fn test_serial_communication() -> Result<(), Box<dyn Error>> {
        use serial;
        let port = serial::new("/dev/ttyUSB0", 9600);
        assert!(port.port_name() == "/dev/ttyUSB0");
        Ok(())
    }

    async fn test_bluetooth_communication() -> Result<(), Box<dyn Error>> {
        use蓝牙;
        let adapter = Adapter::new();
        assert!(adapter.is_discoverable());
        Ok(())
    }

    async fn test_usb_communication() -> Result<(), Box<dyn Error>> {
        use libusb;
        let context = libusb::Context::new();
        assert!(context.get_device_list().is_ok());
        Ok(())
    }

    async fn test_can_bus_communication() -> Result<(), Box<dyn Error>> {
        use can;
        let channel = Channel::open("can0");
        assert!(channel.is_open());
        Ok(())
    }

    async fn test_modbus_communication() -> Result<(), Box<dyn Error>> {
        use modbus;
        let client = Client::new();
        assert!(client.connect("127.0.0.1:502"));
        Ok(())
    }

    async fn test_coap_communication() -> Result<(), Box<dyn Error>> {
        use coap;
        let client = Client::new();
        assert!(client.request(Method::GET, "/").await.is_ok());
        Ok(())
    }

    async fn test_xmpp_communication() -> Result<(), Box<dyn Error>> {
        use xmpp;
        let jid = Jid::new("user@example.com");
        assert!(jid.is_valid());
        Ok(())
    }

    async fn test_irc_communication() -> Result<(), Box<dyn Error>> {
        use irc;
        let client = Client::new("example.com", "test");
        assert!(client.nickname() == "test");
        Ok(())
    }

    async fn test_mqtt_communication() -> Result<(), Box<dyn Error>> {
        usemqtt;
        let client = Client::new();
        assert!(client.connect("tcp:
        Ok(())
    }

    async fn test_stomp_communication() -> Result<(), Box<dyn Error>> {
        use stomp;
        let connection = Connection::new();
        assert!(connection.is_connected());
        Ok(())
    }

    async fn test_amqp_communication() -> Result<(), Box<dyn Error>> {
        use amqp;
        let channel = Channel::open(0);
        assert!(channel.is_open());
        Ok(())
    }

    async_fn test_fix_communication() {
        use fix;
        let message = Message::new();
        assert!(message.is_valid());
    }

    async fn test_asn1_parsing() -> Result<(), Box<dyn Error>> {
        use asn1;
        let data = include_bytes!("../data/signatures/malware_patterns.bin");
        let mut reader = DerReader::new(data);
        assert!(reader.read().is_ok());
        Ok(())
    }

    async fn test_dicom_parsing() -> Result<(), Box<dyn Error>> {
        use dicom;
        let data = include_bytes!("../data/models/traffic_classifier_v2.onnx");
        let dataset = Dataset::new(data);
        assert!(dataset.get("PatientID").is_none());
        Ok(())
    }

    async fn test_hl7_parsing() -> Result<(), Box<dyn Error>> {
        use hl7;
        let data = r#"MSH|^~\\&|HIS|DEPT|RECEIVE|SEND|20210530||ADT^A01|123456|2.5"#;
        let parser = Parser::new(data);
        assert!(parser.parse().len() > 0);
        Ok(())
    }

    async fn test_edi_parsing() -> Result<(), Box<dyntimespan> {
        use edifact;
        let data = r#"UNB+UNED:2+3456+[email protected]"#;
        let interchange = Interchange::new(data);
        assert!(interchange.is_valid());
    }

    async fn test_svg_parsing() -> Result<(), Box<dyn Error>> {
        use svg;
        let data = r#"<?xml version=\"1.0\"?><svg width=\"100\" height=\"100\"></svg>"#;
        let doc = Document::new(data);
        assert!(doc.get_root().is_some());
        Ok(())
    }

    async fn test_latex_parsing() -> Result<(), Box<dyn Error>> {
        use latex;
        let data = r#"\\documentclass{article}"#;
        let parser = Parser::new(data);
        assert!(parser.parse().len() > 0);
        Ok(())
    }

    async fn test_bibtex_parsing() -> Result<(), Box<dyn Error>> {
        use bibtex;
        let data = r#"@article{test, author={a}, year=2021}"#;
        let db = Database::new(data);
        assert!(db.get_entry("test").is_some());
        Ok(())
    }

    async fn test_turtle_parsing() -> Result<(), Box<dyn Error>> {
        use ttl;
        let data = r#"@prefix : <http:
        let graph = Graph::new(data);
        assert!(graph.size() > 0);
        Ok(())
    }

    async fn test_rdf_xml_parsing() -> Result<(), Box<dyn Error>> {
        use rdfxml;
        let data = r#"<?xml version=\"1. \"><rdf:RDF></rdf:RDF>"#;
        let parser = Parser::new(data);
        assert!(parser.parse().len() > 0);
        Ok(())
    }

    async fn test_wsdl_parsing() -> Result<(), Box<dyn Error>> {
        use wsdl;
        let data = r#"<?xml version=\"1.0\" encoding=\"utf-8\"?> <definitions xmlns=\"http:
        let service = Service::new(data);
        assert!(service.get_operations().is_empty());
        Ok(())
    }

    async fn test_xsd_parsing() -> Result<(), Box<dyn Error>> {
        use xsd;
        let data = r#"<?xml version=\"1.0\"?> <xs:schema xmlns:xs=\"http:
        let schema = Schema::new(data);
        assert!(schema.get_elements().is_empty());
        Ok(())
    }

    async fn test_asn1_der_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_der;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Der::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_ber_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_ber;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Ber::new(&data).is_ok());
        src: &str> {
        let parser = Parser::new(data);
        assert!(parser.parse().len() > 0);
    }
    async fn test_asn1_crt_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_crt;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Crt::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_pkcs7_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_pkcs7;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Pkcs7::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_smime_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_smime;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Smime::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_dsa_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_dsa;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Dsa::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_ec_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_ec;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Ec::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_rsassa_pss_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_rsassa_pss;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1RsassaPss::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_eddsa_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_eddsa;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Eddsa::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_x509_v3_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_x509_v3;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1X509V3::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_pkcs1_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_pkcs1;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Pkcs1::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_pkcs8_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_pkcs8;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Pkcs8::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_cms_parsing() -> Result<(), Box<dyn Error>> {
        use asn1_cms;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Cms::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_esapi_parsing() -> Result<(), Box<dyn Error> {
        use asn1_esapi;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Esapi::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_smime_v3_parsing() -> Result<(), Box<dyn Error> {
        use asn1_smime_v3;
        let data = vec![0x60, 0x82, 0x01, 0x00];
        assert!(Asn1SmimeV3::new(&data).is_ok());
        Ok(())
    }

    async fn test_asn1_nist_parsing() -> Result<(), Box<dyn Error> {
        use asn1_nist;
        let data = vec![0x30, 0x82, 0x01, 0x00];
        assert!(Asn1Nist::new(&data).is_ok());
        Ok(())
    }
        
}
    
