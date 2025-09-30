/// Returns the representation of number with given le bits as minimum number of additions/subtractions with powers of two
pub fn neg_pos_sum_of_powers_of_two(bits: Vec<bool>) -> Vec<i8> {
    let mut len = bits.len();
    let mut res = vec![0i8; len + 1];
    let mut l: i32 = -1;
    for i in 0..len {
        if !bits[i] {
            l = -1;
        } else if i == len - 1 || !bits[i + 1] {
            if l == -1 {
                res[i] = 1;
            } else {
                res[i + 1] = 1;
                res[l as usize] = -1;
            }
        } else if l == -1 {
            l = i as i32;
        }
    }

    while len > 0 && res[len] == 0 {
        res.pop();
        len -= 1;
    }

    res
}
