use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use std::collections::HashMap;

fn generate_random_tls_fingerprint() -> String {
    let mut rng = rand::thread_rng();
    (0..5).map(|_| format!("{:x}", rng.gen::<u8>())).collect()
}

fn generate_random_signatures(count: usize) -> HashMap<String, u32> {
    let mut rng = rand::thread_rng();
    let mut signatures = HashMap::new();

    for _ in 0..count {
        let fingerprint = generate_random_tls_fingerprint();
        let score = rng.gen_range(1u32..=10);
        signatures.insert(fingerprint, score);
    }

    signatures
}

fn benchmark_fingerprint_matching(c: &mut Criterion) {
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("fingerprint_matching", |b| {
        b.iter(|| {
            let mut matches = 0;
            for _ in 0..100 {
                let test_fingerprint = generate_random_tls_fingerprint();
                if let Some(score) = test_signatures.get(&test_fingerprint) {
                    matches += *score;
                }
            }
            matches
        });
    });
}

fn benchmark_signature_insertion(c: &mut Criterion) {
    let mut signatures = HashMap::new();

    c.bench_function("signature_insertion", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_lookup(c: &mut Criterion) {
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_lookup", |b| {
        b.iter(|| {
            let mut matches = 0;
            for _ in 0..1000 {
                let test_fingerprint = generate_random_tls_fingerprint();
                if let Some(score) = test_signatures.get(&test_fingerprint) {
                    matches += *score;
                }
            }
            matches
        });
    });
}

fn benchmark_signature_removal(c: &mut Criterion) {
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_removal", |b| {
        b.iter(|| {
            for _ in 0..500 {
                let test_fingerprint = generate_random_tls_fingerprint();
                if let Some(score) = signatures.remove(&test_fingerprint) {
                    score;
                }
            }
        });
    });
}

fn benchmark_signature_update(c: &mut Criterion) {
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_update", |b| {
        b.iter(|| {
            for _ in 0..500 {
                let test_fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(test_fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_iteration(c: &mut Criterion) {
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_iteration", |b| {
        b.iter(|| {
            let mut total_score = 0;
            for (_fingerprint, score) in &test_signatures {
                total_score += *score;
            }
            total_score
        });
    });
}

fn benchmark_signature_clear(c: &mut Criterion) {
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_clear", |b| {
        b.iter(|| {
            signatures.clear();
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_clone(c: &mut Criterion) {
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_clone", |b| {
        b.iter(|| {
            let _cloned_signatures = test_signatures.clone();
        });
    });
}

fn benchmark_signature_capacity(c: &mut Criterion) {
    let mut signatures = HashMap::with_capacity(1000);

    c.bench_function("signature_capacity", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_resize(c: &mut Criterion) {
    let mut signatures = HashMap::new();

    c.bench_function("signature_resize", |b| {
        b.iter(|| {
            signatures.reserve(1000);
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_shrink(c: &mut Criterion) {
    let mut signatures = HashMap::with_capacity(1000);

    c.bench_function("signature_shrink", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
            signatures.shrink_to_fit();
        });
    });
}

fn benchmark_signature_drain(c: &mut Criterion) {
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_drain", |b| {
        b.iter(|| {
            let _drained: HashMap<_, _> = signatures.drain().collect();
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_extend(c: &mut Criterion) {
    let mut signatures = HashMap::new();

    c.bench_function("signature_extend", |b| {
        b.iter(|| {
            let new_signatures = generate_random_signatures(1000);
            signatures.extend(new_signatures);
            signatures.clear();
        });
    });
}

fn benchmark_signature_retain(c: &mut Criterion) {
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_retain", |b| {
        b.iter(|| {
            signatures.retain(|_k, v| *v > 5);
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_par_extend(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = HashMap::new();

    c.bench_function("signature_par_extend", |b| {
        b.iter(|| {
            let new_signatures = (0..1000).map(|_| generate_random_tls_fingerprint())
                .zip((0..1000).map(|_| rand::thread_rng().gen_range(1u32..=10)))
                .collect::<Vec<_>>()
                .into_par_iter()
                .collect();
            signatures.par_extend(new_signatures);
            signatures.clear();
        });
    });
}

fn benchmark_signature_par_retain(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_retain", |b| {
        b.iter(|| {
            signatures.par_retain(|_k, v| *v > 5);
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_par_iter(c: &mut Criterion) {
    use rayon::prelude::*;
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_iter", |b| {
        b.iter(|| {
            let total_score: u32 = test_signatures.par_iter().map(|(_k, v)| *v).sum();
            total_score
        });
    });
}

fn benchmark_signature_par_drain(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_drain", |b| {
        b.iter(|| {
            let _drained: HashMap<_, _> = signatures.par_drain().collect();
            for _ in 0..1000 {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            }
        });
    });
}

fn benchmark_signature_par_capacity(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = HashMap::with_capacity(1000);

    c.bench_function("signature_par_capacity", |b| {
        b.iter(|| {
            (0..1000).into_par_iter().for_each(|_| {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            });
        });
    });
}

fn benchmark_signature_par_resize(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = HashMap::new();

    c.bench_function("signature_par_resize", |b| {
        b.iter(|| {
            signatures.reserve(1000);
            (0..1000).into_par_iter().for_each(|_| {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            });
        });
    });
}

fn benchmark_signature_par_shrink(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = HashMap::with_capacity(1000);

    c.bench_function("signature_par_shrink", |b| {
        b.iter(|| {
            (0..1000).into_par_iter().for_each(|_| {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            });
            signatures.shrink_to_fit();
        });
    });
}

fn benchmark_signature_par_clear(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = HashMap::new();

    c.bench_function("signature_par_clear", |b| {
        b.iter(|| {
            (0..1000).into_par_iter().for_each(|_| {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            });
            signatures.clear();
        });
    });
}

fn benchmark_signature_par_clone(c: &mut Criterion) {
    use rayon::prelude::*;
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_clone", |b| {
        b.iter(|| {
            let _cloned_signatures: HashMap<_, _> = test_signatures.par_iter().cloned().collect();
        });
    });
}

fn benchmark_signature_par_update(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_update", |b| {
        b.iter(|| {
            (0..500).into_par_iter().for_each(|_| {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            });
        });
    });
}

fn benchmark_signature_par_remove(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_remove", |b| {
        b.iter(|| {
            (0..500).into_par_iter().for_each(|_| {
                let test_fingerprint = generate_random_tls_fingerprint();
                if let Some(score) = signatures.remove(&test_fingerprint) {
                    score;
                }
            });
        });
    });
}

fn benchmark_signature_par_lookup(c: &mut Criterion) {
    use rayon::prelude::*;
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_lookup", |b| {
        b.iter(|| {
            let mut matches = 0;
            (0..1000).into_par_iter().for_each(|_| {
                let test_fingerprint = generate_random_tls_fingerprint();
                if let Some(score) = test_signatures.get(&test_fingerprint) {
                    matches += *score;
                }
            });
            matches
        });
    });
}

fn benchmark_signature_par_matching(c: &mut Criterion) {
    use rayon::prelude::*;
    let test_signatures = generate_random_signatures(1000);

    c.bench_function("signature_par_matching", |b| {
        b.iter(|| {
            let mut matches = 0;
            (0..100).into_par_iter().for_each(|_| {
                let test_fingerprint = generate_random_tls_fingerprint();
                if let Some(score) = test_signatures.get(&test_fingerprint) {
                    matches += *score;
                }
            });
            matches
        });
    });
}

fn benchmark_signature_par_insertion(c: &mut Criterion) {
    use rayon::prelude::*;
    let mut signatures = HashMap::new();

    c.bench_function("signature_par_insertion", |b| {
        b.iter(|| {
            (0..1000).into_par_iter().for_each(|_| {
                let fingerprint = generate_random_tls_fingerprint();
                let score = rand::thread_rng().gen_range(1u32..=10);
                signatures.insert(fingerprint, score);
            });
        });
    });
}

criterion_group!(
    benches,
    benchmark_fingerprint_matching,
    benchmark_signature_insertion,
    benchmark_signature_lookup,
    benchmark_signature_removal,
    benchmark_signature_update,
    benchmark_signature_iteration,
    benchmark_signature_clear,
    benchmark_signature_clone,
    benchmark_signature_capacity,
    benchmark_signature_resize,
    benchmark_signature_shrink,
    benchmark_signature_drain,
    benchmark_signature_extend,
    benchmark_signature_retain,
    benchmark_signature_par_extend,
    benchmark_signature_par_retain,
    benchmark_signature_par_iter,
    benchmark_signature_par_drain,
    benchmark_signature_par_capacity,
    benchmark_signature_par_resize,
    benchmark_signature_par_shrink,
    benchmark_signature_par_clear,
    benchmark_signature_par_clone,
    benchmark_signature_par_update,
    benchmark_signature_par_remove,
    benchmark_signature_par_lookup,
    benchmark_signature_par_matching,
    benchmark_signature_par_insertion
);
criterion_main!(benches);
