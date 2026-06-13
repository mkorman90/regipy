use criterion::{black_box, criterion_group, criterion_main, Criterion};
use regipy_rs::RegistryHive;

/// Generate a synthetic hive file that mimics a real NTUSER.DAT structure.
fn generate_test_hive(num_keys: u32, values_per_key: u32) -> Vec<u8> {
    // Each NK record is ~100 bytes, each VK record is ~30 bytes
    // Estimate: 1000 keys * 100 bytes + 3000 values * 30 bytes = 190KB
    let hive_size = (num_keys as usize) * 128 + (num_keys as usize) * (values_per_key as usize) * 32;
    let mut data = vec![0u8; hive_size.max(65536)];
    
    data[0..4].copy_from_slice(b"regf");
    let name = "NTUSER.DAT";
    for (i, c) in name.encode_utf16().enumerate() {
        data[48 + i * 2] = (c & 0xFF) as u8;
        data[48 + i * 2 + 1] = (c >> 8) as u8;
    }
    data[28..32].copy_from_slice(&0u32.to_le_bytes());
    let hbin_size = data.len() - 4096;
    data[40..44].copy_from_slice(&(hbin_size as u32).to_le_bytes());
    
    data[4096..4100].copy_from_slice(b"hbin");
    data[4100..4104].copy_from_slice(&0u32.to_le_bytes());
    data[4104..4108].copy_from_slice(&(hbin_size as u32).to_le_bytes());
    
    let mut offset = 4096;
    
    for i in 0..num_keys {
        let nk_size = 76 + 8;
        data[offset..offset + 4].copy_from_slice(&(-nk_size as i32).to_le_bytes());
        data[offset + 4..offset + 6].copy_from_slice(b"nk");
        offset += 6;
        
        data[offset..offset + 8].copy_from_slice(&((i as i64) * 10000000000i64).to_le_bytes());
        offset += 8;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        let values_count = if i % 3 == 0 { values_per_key as u32 } else { 0 };
        data[offset..offset + 4].copy_from_slice(&values_count.to_le_bytes());
        offset += 4;
        let values_offset = offset - 4096;
        data[offset..offset + 4].copy_from_slice(&((values_offset as u32).to_le_bytes()));
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;
        let key_name = format!("Key{:04}", i);
        let key_name_size = key_name.len() as u16;
        data[offset..offset + 2].copy_from_slice(&key_name_size.to_le_bytes());
        offset += 2;
        data[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
        offset += 2;
        for (j, b) in key_name.bytes().enumerate() {
            data[offset + j] = b;
        }
        offset += key_name_size as usize;
        
        if values_count > 0 {
            for j in 0..values_count {
                let vk_offset = offset - 4096;
                data[offset..offset + 4].copy_from_slice(&((vk_offset as u32).to_le_bytes()));
                offset += 4;
                
                data[offset..offset + 2].copy_from_slice(b"vk");
                offset += 2;
                let val_name = format!("Value{:04}", j);
                let val_name_size = val_name.len() as u16;
                data[offset..offset + 2].copy_from_slice(&val_name_size.to_le_bytes());
                offset += 2;
                data[offset..offset + 4].copy_from_slice(&4u32.to_le_bytes());
                offset += 4;
                data[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
                offset += 4;
                data[offset..offset + 4].copy_from_slice(&1u32.to_le_bytes());
                offset += 4;
                data[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
                offset += 2;
                data[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
                offset += 2;
                for (k, b) in val_name.bytes().enumerate() {
                    data[offset + k] = b;
                }
                offset += val_name_size as usize;
            }
        }
    }
    
    data
}

fn parse_hive(c: &mut Criterion) {
    let mut group = c.benchmark_group("hive_parsing");
    
    let small_hive = generate_test_hive(100, 5);
    group.bench_function("parse_small_hive_100keys", |b| {
        b.iter(|| {
            let hive = RegistryHive::from_bytes(small_hive.clone());
            black_box(hive)
        });
    });
    
    let medium_hive = generate_test_hive(500, 10);
    group.bench_function("parse_medium_hive_500keys", |b| {
        b.iter(|| {
            let hive = RegistryHive::from_bytes(medium_hive.clone());
            black_box(hive)
        });
    });
    
    let large_hive = generate_test_hive(1000, 5);
    group.bench_function("parse_large_hive_1000keys", |b| {
        b.iter(|| {
            let hive = RegistryHive::from_bytes(large_hive.clone());
            black_box(hive)
        });
    });
    
    group.finish();
}

fn iterate_subkeys(c: &mut Criterion) {
    let hive = RegistryHive::from_bytes(generate_test_hive(1000, 5)).unwrap();
    
    c.bench_function("iterate_1000_keys", |b| {
        b.iter(|| {
            let count = hive.recurse_subkeys().count();
            black_box(count)
        });
    });
}

fn get_key(c: &mut Criterion) {
    let hive = RegistryHive::from_bytes(generate_test_hive(1000, 5)).unwrap();
    
    c.bench_function("get_key_1000_keys", |b| {
        b.iter(|| {
            let result = hive.get_key("Key0500");
            black_box(result)
        });
    });
}

criterion_group!(benches, parse_hive, iterate_subkeys, get_key);
criterion_main!(benches);
