# AES-NI Ciphertext Hashing Implementation

## Context
The TODO at `examples/groth16_garble.rs:219` requires implementing ciphertext hashing for the streaming garbled circuit verifier. Ciphertexts arrive as `GarbledTableEntry = (usize, S)` where `S` is a 32-byte garbled wire label via crossbeam channels.

## Two Implementation Approaches

### Approach 1: Sequential Hashing
Process each ciphertext individually as it arrives from the channel.

```rust
std::thread::spawn(move || {
    let mut running_hash = [0u8; 16]; // Initial state
    let key = [0x42u8; 16]; // Fixed key for hashing
    
    while let Ok((gate_id, ciphertext)) = receiver.recv() {
        // Hash: running_hash = AES(key, running_hash ⊕ ciphertext[0..16])
        let input = xor_arrays(&running_hash, &ciphertext.0[0..16]);
        running_hash = aes128_encrypt_block(key, input)
            .expect("AES-NI should be available");
    }
    
    println!("Final sequential hash: {:02x?}", running_hash);
});
```

**Performance**: Baseline - 1 AES operation per ciphertext
**Benefits**: Simple, deterministic, constant memory usage
**Use case**: When ciphertext order matters or memory is constrained

### Approach 2: Batched 8-Block SIMD Hashing  
Collect 8 ciphertexts, process in parallel with AES-NI SIMD, then aggregate.

```rust
std::thread::spawn(move || {
    let mut batch_buffer = Vec::with_capacity(8);
    let mut running_hash = [0u8; 16];
    let key1 = [0x42u8; 16]; // Key for batch processing
    let key2 = [0x24u8; 16]; // Key for aggregation
    
    while let Ok((gate_id, ciphertext)) = receiver.recv() {
        batch_buffer.push(ciphertext.0);
        
        if batch_buffer.len() == 8 {
            // Process 8 ciphertexts in parallel
            let (h0,h1,h2,h3,h4,h5,h6,h7) = encrypt8_blocks(
                key1, 
                batch_buffer[0], batch_buffer[1], batch_buffer[2], batch_buffer[3],
                batch_buffer[4], batch_buffer[5], batch_buffer[6], batch_buffer[7]
            ).expect("AES-NI should be available");
            
            // Aggregate: XOR all results then AES encrypt
            let xor_result = xor_8_arrays(&[h0,h1,h2,h3,h4,h5,h6,h7]);
            let batch_hash = aes128_encrypt_block(key2, xor_result)
                .expect("AES-NI should be available");
            
            // Update running hash
            let combined = xor_arrays(&running_hash, &batch_hash);
            running_hash = aes128_encrypt_block(key1, combined)
                .expect("AES-NI should be available");
            
            batch_buffer.clear();
        }
    }
    
    // Handle remaining ciphertexts (< 8) with sequential approach
    for remaining_ciphertext in batch_buffer {
        let input = xor_arrays(&running_hash, &remaining_ciphertext[0..16]);
        running_hash = aes128_encrypt_block(key1, input)
            .expect("AES-NI should be available");
    }
    
    println!("Final batched hash: {:02x?}", running_hash);
});
```

**Performance**: ~6x faster than sequential approach
**Benefits**: Maximum SIMD utilization, high throughput
**Use case**: High-performance scenarios where latency is acceptable

## Required AES-NI Extension

Add this method to `src/core/gate/garbling/aes_ni.rs` in the `Aes128` implementation:

```rust
/// Encrypt eight blocks in parallel (near-peak throughput on many CPUs).
#[inline]
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn encrypt8_blocks(
    &self,
    b0: [u8; 16], b1: [u8; 16], b2: [u8; 16], b3: [u8; 16],
    b4: [u8; 16], b5: [u8; 16], b6: [u8; 16], b7: [u8; 16],
) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
    let mut s0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
    let mut s1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);
    let mut s2 = _mm_loadu_si128(b2.as_ptr() as *const __m128i);
    let mut s3 = _mm_loadu_si128(b3.as_ptr() as *const __m128i);
    let mut s4 = _mm_loadu_si128(b4.as_ptr() as *const __m128i);
    let mut s5 = _mm_loadu_si128(b5.as_ptr() as *const __m128i);
    let mut s6 = _mm_loadu_si128(b6.as_ptr() as *const __m128i);
    let mut s7 = _mm_loadu_si128(b7.as_ptr() as *const __m128i);

    let rk0 = self.round_keys[0];
    s0 = _mm_xor_si128(s0, rk0); s1 = _mm_xor_si128(s1, rk0);
    s2 = _mm_xor_si128(s2, rk0); s3 = _mm_xor_si128(s3, rk0);
    s4 = _mm_xor_si128(s4, rk0); s5 = _mm_xor_si128(s5, rk0);
    s6 = _mm_xor_si128(s6, rk0); s7 = _mm_xor_si128(s7, rk0);

    for r in 1..10 {
        let rk = self.round_keys[r];
        s0 = _mm_aesenc_si128(s0, rk); s1 = _mm_aesenc_si128(s1, rk);
        s2 = _mm_aesenc_si128(s2, rk); s3 = _mm_aesenc_si128(s3, rk);
        s4 = _mm_aesenc_si128(s4, rk); s5 = _mm_aesenc_si128(s5, rk);
        s6 = _mm_aesenc_si128(s6, rk); s7 = _mm_aesenc_si128(s7, rk);
    }
    let rk_last = self.round_keys[10];
    s0 = _mm_aesenclast_si128(s0, rk_last); s1 = _mm_aesenclast_si128(s1, rk_last);
    s2 = _mm_aesenclast_si128(s2, rk_last); s3 = _mm_aesenclast_si128(s3, rk_last);
    s4 = _mm_aesenclast_si128(s4, rk_last); s5 = _mm_aesenclast_si128(s5, rk_last);
    s6 = _mm_aesenclast_si128(s6, rk_last); s7 = _mm_aesenclast_si128(s7, rk_last);

    let mut o0 = [0u8; 16]; let mut o1 = [0u8; 16];
    let mut o2 = [0u8; 16]; let mut o3 = [0u8; 16];
    let mut o4 = [0u8; 16]; let mut o5 = [0u8; 16];
    let mut o6 = [0u8; 16]; let mut o7 = [0u8; 16];
    _mm_storeu_si128(o0.as_mut_ptr() as *mut __m128i, s0);
    _mm_storeu_si128(o1.as_mut_ptr() as *mut __m128i, s1);
    _mm_storeu_si128(o2.as_mut_ptr() as *mut __m128i, s2);
    _mm_storeu_si128(o3.as_mut_ptr() as *mut __m128i, s3);
    _mm_storeu_si128(o4.as_mut_ptr() as *mut __m128i, s4);
    _mm_storeu_si128(o5.as_mut_ptr() as *mut __m128i, s5);
    _mm_storeu_si128(o6.as_mut_ptr() as *mut __m128i, s6);
    _mm_storeu_si128(o7.as_mut_ptr() as *mut __m128i, s7);
    (o0, o1, o2, o3, o4, o5, o6, o7)
}
```

And add the corresponding safe wrapper function:

```rust
/// Safe wrapper: eight blocks in parallel with runtime AES-NI detection.
pub fn aes128_encrypt8_blocks(
    key: [u8; 16],
    b0: [u8; 16], b1: [u8; 16], b2: [u8; 16], b3: [u8; 16],
    b4: [u8; 16], b5: [u8; 16], b6: [u8; 16], b7: [u8; 16],
) -> Option<([u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16], [u8; 16])> {
    let cipher = Aes128::new(key)?;
    Some(unsafe { cipher.encrypt8_blocks(b0, b1, b2, b3, b4, b5, b6, b7) })
}
```

## Utility Functions

```rust
// XOR two 16-byte arrays
fn xor_arrays(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

// XOR eight 16-byte arrays
fn xor_8_arrays(arrays: &[[u8; 16]; 8]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for array in arrays {
        for i in 0..16 {
            result[i] ^= array[i];
        }
    }
    result
}
```

## Performance Expectations

### Sequential Approach
- **Throughput**: ~1 AES operation per ciphertext
- **Latency**: Immediate processing
- **Memory**: Constant (16 bytes running state)

### Batched 8-Block Approach  
- **Throughput**: ~6x faster than sequential
- **Latency**: Up to 8 ciphertexts buffering delay
- **Memory**: 8×32 = 256 bytes buffer + 16 bytes running state

## Integration with Existing Code

Replace the TODO at `examples/groth16_garble.rs:219` with:

```rust
std::thread::spawn(move || {
    println!("Starting ciphertext hashing thread...");
    
    // Choose approach based on performance requirements
    let use_batched = true; // Set to false for sequential approach
    
    if use_batched {
        // Implement batched approach here
        let mut batch_buffer = Vec::with_capacity(8);
        let mut running_hash = [0u8; 16];
        let key1 = [0x42u8; 16];
        let key2 = [0x24u8; 16];
        
        while let Ok(ciphertext) = receiver.recv() {
            batch_buffer.push(ciphertext.1.0); // Extract S from GarbledTableEntry
            
            if batch_buffer.len() == 8 {
                // Process batch (implementation as shown above)
                // ... batched processing logic
                batch_buffer.clear();
            }
        }
        
        // Handle remaining ciphertexts
        // ... sequential processing for remainder
        
    } else {
        // Implement sequential approach here  
        let mut running_hash = [0u8; 16];
        let key = [0x42u8; 16];
        
        while let Ok(ciphertext) = receiver.recv() {
            // Sequential processing (implementation as shown above)
            // ... sequential processing logic
        }
    }
    
    println!("Ciphertext hashing thread completed");
});
```

## Testing Strategy

1. **Correctness**: Verify both approaches produce consistent results with known test vectors
2. **Performance**: Benchmark both approaches with realistic ciphertext volumes  
3. **Integration**: Test with full Groth16 verification to ensure no regressions

## Security Considerations

- Both approaches use deterministic AES-based hashing
- Keys should be generated from secure random source in production
- XOR aggregation maintains diffusion properties when followed by AES
- Running hash state provides sequential dependency to prevent reordering attacks

## Future Optimizations

- Consider 16-block or 32-block batching for even higher throughput
- Implement NUMA-aware processing for multi-socket systems
- Add adaptive batching based on ciphertext arrival rate