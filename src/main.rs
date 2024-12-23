//! Simplified Data Encryption Standard
//!
//! S-DES is a simplified version of DES
//! made for educational purposes
//!
//! It uses 8 bit blocks and a 10 bit key

// substitution box S0
const S0: [[u8; 4]; 4] = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
];

// substitution box S1
const S1: [[u8; 4]; 4] = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
];

// permutation of a 10 bit string into a 10 bit string:
// [b0,b1,b2,b3,b4,b5,b6,b7,b8,b9] -> [b2,b4,b1,b6,b3,b9,b0,b8,b7,b5]
fn p10(key: u16) -> u16 {
    let p10_table = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
    let mut result: u16 = 0;
    
    for (i, &pos) in p10_table.iter().enumerate() {
        let bit = (key >> (10 - pos)) & 1;
        result |= bit << (9 - i);
    }
    result
}

// permutation of a 10 bit string into a 8 bit string:
// [b0,b1,b2,b3,b4,b5,b6,b7,b8,b9] -> [b5,b2,b6,b3,b7,b4,b9,b8]
fn p8(key: u16) -> u8 {
    let p8_table = [6, 3, 7, 4, 8, 5, 10, 9];
    let mut result: u8 = 0;
    
    for (i, &pos) in p8_table.iter().enumerate() {
        let bit = (key >> (10 - pos)) & 1;
        result |= (bit as u8) << (7 - i);
    }
    result
}

// perform a left shift of n on LOW and HIGH separately, returning
// the concatenation of the shifted HIGH and LOW parts of key
fn left_shift(key: u16, n: u32) -> u16 {
    let left = (key >> 5) & 0x1F;
    let right = key & 0x1F;
    
    let shifted_left = ((left << n) | (left >> (5 - n))) & 0x1F;
    let shifted_right = ((right << n) | (right >> (5 - n))) & 0x1F;
    
    (shifted_left << 5) | shifted_right
}

// generate SK1 and SK2 from the cipher key
fn generate_subkeys(key: u16) -> (u8, u8) {
    let p10_key = p10(key);
    let ls1 = left_shift(p10_key, 1);
    let ls2 = left_shift(ls1, 2);
    
    let k1 = p8(ls1);
    let k2 = p8(ls2);
    
    (k1, k2)
}


// [b0,b1,b2,b3,b4,b5,b6,b7] -> [b1,b5,b2,b0,b3,b7,b4,b6]
fn initial_permutation(input: u8) -> u8 {
    let ip_table = [2, 6, 3, 1, 4, 8, 5, 7];
    let mut result: u8 = 0;
    
    for (i, &pos) in ip_table.iter().enumerate() {
        let bit = (input >> (8 - pos)) & 1;
        result |= bit << (7 - i);
    }
    result
}

// [b0,b1,b2,b3,b4,b5,b6,b7] -> [b3,b0,b2,b4,b6,b1,b7,b5]
fn inverse_initial_permutation(input: u8) -> u8 {
    let ip_inv_table = [4, 1, 3, 5, 7, 2, 8, 6];
    let mut result: u8 = 0;
    
    for (i, &pos) in ip_inv_table.iter().enumerate() {
        let bit = (input >> (8 - pos)) & 1;
        result |= bit << (7 - i);
    }
    result
}

// expands the inputs HIGH and LOW parts of 4 bits each into 
// 8 bit HIGH and LOW parts, in order to match the SK's size
fn expansion_permutation(input: u8) -> u8 {
    let ep_table = [4, 1, 2, 3, 2, 3, 4, 1];
    let mut result: u8 = 0;
    
    for (i, &pos) in ep_table.iter().enumerate() {
        let bit = (input >> (4 - pos)) & 1;
        result |= bit << (7 - i);
    }
    result
}

// [b0,b1,b2,b3] -> [b1,b3,b2,b0]
fn p4(input: u8) -> u8 {
    let p4_table = [2, 4, 3, 1];
    let mut result: u8 = 0;
    
    for (i, &pos) in p4_table.iter().enumerate() {
        let bit = (input >> (4 - pos)) & 1;
        result |= bit << (3 - i);
    }
    result
}

// lookup values from the SBOXes
fn s_box_lookup(input: u8, sbox: [[u8; 4]; 4]) -> u8 {
    let row = ((input & 0b10000) >> 3) | (input & 1);
    let col = (input >> 1) & 0b11;
    sbox[row as usize][col as usize]
}

// Feistel function
fn f_function(input: u8, subkey: u8) -> u8 {
    // expand 4bit to 8bit
    let expanded = expansion_permutation(input);

    let xored = expanded ^ subkey;
    
    let left_half = (xored >> 4) & 0x0F;
    let right_half = xored & 0x0F;
    
    let s0_result = s_box_lookup(left_half, S0);
    let s1_result = s_box_lookup(right_half, S1);
    
    let combined = (s0_result << 2) | s1_result;
    p4(combined)
}

// Feistel K function
fn fk(input: u8, subkey: u8) -> u8 {
    let left = (input >> 4) & 0x0F;
    let right = input & 0x0F;
    
    let f_result = f_function(right, subkey);
    let new_left = left ^ f_result;
    
    ((new_left << 4) | right) & 0xFF
}

// switch HIGH and LOW
fn sw(input: u8) -> u8 {
    ((input & 0x0F) << 4) | ((input >> 4) & 0x0F)
}

fn encrypt(plaintext: u8, k1: u8, k2: u8) -> u8 {
    let ip = initial_permutation(plaintext);
    let after_fk1 = fk(ip, k1);
    let after_sw = sw(after_fk1);
    let after_fk2 = fk(after_sw, k2);
    inverse_initial_permutation(after_fk2)
}

fn decrypt(ciphertext: u8, k1: u8, k2: u8) -> u8 {
    let ip = initial_permutation(ciphertext);
    let after_fk1 = fk(ip, k2);  // Note: k2 is used first
    let after_sw = sw(after_fk1);
    let after_fk2 = fk(after_sw, k1);  // Then k1
    inverse_initial_permutation(after_fk2)
}

fn main() {
    println!(" 
 $$$$$$\\         $$$$$$$\\  $$$$$$$$\\  $$$$$$\\  
$$  __$$\\        $$  __$$\\ $$  _____|$$  __$$\\ 
$$ /  \\__|       $$ |  $$ |$$ |      $$ /  \\__|
\\$$$$$$\\ $$$$$$\\ $$ |  $$ |$$$$$\\    \\$$$$$$\\  
 \\____$$\\______|$$ |  $$ |$$  __|    \\____$$\\ 
$$\\   $$ |       $$ |  $$ |$$ |      $$\\   $$ |
\\$$$$$$  |       $$$$$$$  |$$$$$$$$\\ \\$$$$$$  |
 \\______/        \\_______/ \\________| \\______/\n\n");

    let key: u16 = 0b1010000010;
    let plaintext: u8 = 0b11010111;

    println!("Original Key (10 bits): {:010b}", key);
    println!("Original Data (8 bits): {:08b}", plaintext);

    // Generate subkeys
    let (k1, k2) = generate_subkeys(key);
    println!("Subkey K1 (8 bits):     {:08b}", k1);
    println!("Subkey K2 (8 bits):     {:08b}", k2);

    // Encrypt
    let ciphertext = encrypt(plaintext, k1, k2);
    println!("Encrypted (8 bits):     {:08b}", ciphertext);

    // Decrypt
    let decrypted = decrypt(ciphertext, k1, k2);
    println!("Decrypted (8 bits):     {:08b}", decrypted);
}
