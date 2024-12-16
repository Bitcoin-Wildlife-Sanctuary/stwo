#![allow(incomplete_features, trivial_bounds)]
#![cfg_attr(
    all(target_arch = "x86_64", target_feature = "avx512f"),
    feature(stdarch_x86_avx512)
)]
#![feature(
    array_chunks,
    iter_array_chunks,
    exact_size_is_empty,
    get_many_mut,
    int_roundings,
    assert_matches,
    portable_simd,
    trait_upcasting,
    trivial_bounds
)]

pub mod constraint_framework;
pub mod core;
pub mod examples;
pub mod math;
