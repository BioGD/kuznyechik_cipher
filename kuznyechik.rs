extern crate num_bigint;
extern crate num_traits;
use encoding_rs::*;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::Zero;
use std::str::FromStr;

use std::io::Read;
use std::u128;
use std::io;

use std::fs::File;
use std::io::Write;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;


const POL: [bool; 9] = [true, true, true, false, false, false, false, true, true];
const S_BOX:[u8; 256] = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182];

fn main() {
    let mut mes_bits: Vec<u128> = Vec::with_capacity(256);

    let func:u8;
    {
        println!("Выберите функцию:\n0)Шифрование\n1)Расшифрование");
        let mut func_str = String::new();
        io::stdin().read_line(&mut func_str).expect("err input text");
        func = func_str.trim().parse().expect("Mod err");
    } 
    
    if func == 0{
        let mut key:BigUint = BigUint::zero();
        let iv: u128 = generate_iv();

        let k_mod:u8;
        {
        println!("Выберите функцию использования ключа:\n0)Ввести ключ\n1)Сгенерировать ключ");
        let mut k_mod_str = String::new(); 
        io::stdin().read_line(&mut k_mod_str).expect("err input text");
        k_mod = k_mod_str.trim().parse().expect("Mod err");
        }

        if  k_mod == 0{
            println!("Введите ключ:");
            let mut key_str = String::new();
            io::stdin().read_line(&mut key_str).expect("err input text");
            key_str = key_str.trim_end().to_owned();
            key = BigUint::from_str(key_str.as_str()).unwrap();
        }
        else{
            key = generate_256_bit_key();
        }

        println!("Развертывание раундовых ключей...");
        let key_mas = slay_key(&key);
        println!("Ключи развернуты.");

        let mut message = String::new();
            
        println!("Введите сообщение:");
        io::stdin().read_line(&mut message).expect("err input text");
        println!("Шифрование сообщения...");

        message = adapt_mes(message);
        mes_bits = string_to_bits(&message);
        let counters_vec = encrip_counters(iv, mes_bits.len(), &key_mas);
            
        mes_bits = kuzya(&counters_vec, &mut mes_bits, 0);

        let enc_message = bits_to_string(&mes_bits);
        println!("Шифртекст:\n{}", enc_message);

        let mes_enbits = bits_format_to_str(&mut mes_bits);
        write_text(&mes_enbits);
    }

    else if func == 1{
        let mut key:BigUint = BigUint::zero();
        let iv: u128;

        {
            println!("Введите ключ:");
            let mut key_str = String::new();
            io::stdin().read_line(&mut key_str).expect("err input text");
            key_str = key_str.trim_end().to_owned();
            key = BigUint::from_str(key_str.as_str()).unwrap();
        }

        {
            println!("Введите инициализирующий вектор:");
            let mut iv_str = String::new();
            io::stdin().read_line(&mut iv_str).expect("err input text");
            iv_str = iv_str.trim_end().to_owned();
            iv = u128::from_str(iv_str.as_str()).unwrap();
        }

        println!("Развертывание раундовых ключей...");
        let key_mas = slay_key(&key);
        println!("Ключи развернуты.");

        println!("Расшифрование сообщения...");

        let message = read_text();

        mes_bits = from_file_to_bits(&message, &mut mes_bits);
        let counters_vec = encrip_counters(iv, mes_bits.len(), &key_mas);
            
        mes_bits = kuzya(&counters_vec, &mut mes_bits, 1);
            
        let dec_message = bits_to_string(&mes_bits);
            
        println!("Сообщение:\n{}",dec_message);
        }

    else{println!("Указана некорректная функция.");}
        
    println!("Программа завершина. Нажмите Enter для выхода..");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Err");    
}

fn generate_256_bit_key() -> BigUint {
    println!("Генерация ключа...");

    // Создаем генератор случайных чисел с использованием криптографически безопасного источника
    let mut rng = ChaCha8Rng::from_entropy();

    // Генерируем 256-битный ключ (32 байта)
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes);

    // Преобразуем байты в BigUint
    let key = BigUint::from_bytes_be(&key_bytes);

    println!("Сгенерированный ключ: {}", key);

    key
}

fn generate_iv() -> u128 {
    // Создаем генератор случайных чисел с использованием криптографически безопасного источника
    let mut rng = ChaCha8Rng::from_entropy();

    // Генерируем случайное 128-битное число
    let random_number: u128 = rng.gen();

    println!("Сгенерированный инициализирующий вектор: {}", random_number);

    random_number
}

fn from_file_to_bits(message: &String, mes_bits: &mut Vec<u128>) -> Vec<u128>{
    let chunk_size = 128;
    let mut start = 0;

    while start < message.len() {
        let end = std::cmp::min(start + chunk_size, message.len());
        let chunk = &message[start..end];
        let num = match u128::from_str_radix(chunk, 2) {
            Ok(num) => num,
                Err(e) => {
                println!("Ошибка при преобразовании: {}", e);
                return vec![];
                }
            };
        mes_bits.push(num);
        start += chunk_size;
    }
    mes_bits.clone()
}


fn read_text() -> String{
    // Read a file in the local file system
    let mut data_file = File::open("cipher_text.txt").unwrap();

    // Create an empty mutable string
    let mut file_content = String::new();

    // Copy contents of file to a mutable string
    data_file.read_to_string(&mut file_content).unwrap();
    file_content
}

fn write_text(new_message: &String){
    // Create a file
    let mut data_file = File::create("cipher_text.txt").expect("creation failed");
    // Write contents to the file
    data_file.write(new_message.as_bytes()).expect("write failed");
    println!("Биты зашифрованного сообщения успешно записаны в файл."); 
}

fn string_to_bits(mes: &String) -> Vec<u128> {
    let mut blocks: Vec<u128> = Vec::new();
    let mut current_block: u128 = 0;
    let mut bit_offset = 0;

    let (encoded, _, _) = UTF_8.encode(mes);
    for byte in encoded.into_owned() {
        current_block |= (byte as u128) << (120 - bit_offset);
        bit_offset += 8;

        if bit_offset >= 128 {
            blocks.push(current_block);
            current_block = 0;
            bit_offset = 0;
        }
    }

    if bit_offset > 0 {
        blocks.push(current_block);
    }

    blocks
}

fn bits_to_string(blocks: &Vec<u128>) -> String {
    let mut bytes = Vec::new();

    for &block in blocks {
        for i in 0..16 {
            let byte = ((block >> (120 - i * 8)) & 0xFF) as u8;
            bytes.push(byte);
        }
    }

    // Попытка декодировать байты в строку UTF-8
    let (decoded, _, had_errors) = UTF_8.decode(&bytes);
    if had_errors {
        eprintln!("Warning: Decoding errors occurred.");
    }

    // Удаление последних незначащих пробелов
    decoded.trim_end().to_owned()
}

fn bits_format_to_str(mes_bits: &mut Vec<u128>) -> String{
    let mut mes_enbits = String::new();

    for i in 0..mes_bits.len(){
        let part_mes = format!("{:b}",mes_bits[i]);
        let diff = 128 - part_mes.len();
        for _i in 0..diff{
            mes_enbits.push_str(&"0");
        }    
        mes_enbits.push_str(&part_mes); 
    }
    mes_enbits
}

fn adapt_mes(mut text: String) -> String{
    while text.len() % 16 != 0{
        text.push_str(" "); 
    }
    text
}

fn kuzya(counters_vec: &Vec<u128>, mes_blocks: &mut Vec<u128>, _mod_w: u8) -> Vec<u128>{
    for i in 0..mes_blocks.len(){
        mes_blocks[i] = mes_blocks[i] ^ counters_vec[i];
    }
    mes_blocks.clone()
}

fn kuzya_en(block: &mut u128, key_mas:[u128; 10]) -> u128{
    for _i in 0..9{
        *block = block_replace_encrip(block);
        *block = interfere_blocks_encrip(block);
    }
    *block = *block ^ key_mas[9];
    *block
}

// fn kuzya_dec(block: &mut u128, key_mas:[u128; 10]) -> u128{
//     for i in 0..9{
//         *block = *block ^ key_mas[9 - i];
//         *block = interfere_blocks_decrip(block);
//         *block = block_replace_decrip(block);
//     }
//     *block = *block ^ key_mas[0];
//     *block
// }

fn encrip_counters(iv: u128, count_mesblocks:usize, key_mas: &[u128; 10]) -> Vec<u128>{
    let mut counters_vec:Vec<u128> = Vec::new();
    counters_vec.push(iv);
    for i in 0..count_mesblocks - 1{
        counters_vec.push(counters_vec[i].clone() + 1);
    }

    for i in 0..counters_vec.len(){
        counters_vec[i] = kuzya_en(&mut counters_vec[i], *key_mas);
    }

    counters_vec
}   

fn slay_key(key: &BigUint) -> [u128; 10]{
    let mut key_mas = [0u128; 10];
    let mut key_const = [0u128; 32];
    let mut temp_key = key.clone();

    let mut part = temp_key.clone() & BigUint::from(u128::MAX);
    key_mas[1] = part.to_u128().unwrap();
    temp_key >>= 128;

    part = temp_key.clone() & BigUint::from(u128::MAX);
    key_mas[0] = part.to_u128().unwrap();

    for i in 0..32{
        let vec_i = (i + 1) as u128;
        key_const[i] = vec_i;
        key_const[i] = interfere_blocks_encrip(&mut key_const[i]);

    }

    press_f(&mut key_mas, &key_const);

    key_mas
}

fn press_f(key_mas: &mut [u128; 10], key_const: &[u128; 32]){
    for i in 0..4{
    let mut key_res1: u128;
    let mut key_res2: u128 = key_mas[i * 2 + 1];
    let mut bridge: u128;

    key_res1 = key_mas[i  * 2] ^ key_const[i * 8];
    key_res1 = block_replace_encrip(&key_res1);
    key_res1 = interfere_blocks_encrip(&mut key_res1);
    
    key_res1 = key_res1 ^ key_res2;
    key_res2 = key_mas[i * 2];

    for j in (i * 8 + 1)..(i * 8 + 8){
        bridge = key_res1;
        key_res1 = key_res1 ^ key_const[j];
        key_res1 = block_replace_encrip(&key_res1);
        key_res1 = interfere_blocks_encrip(&mut key_res1);
    
        key_res1 = key_res1 ^ key_res2;
        key_res2 = bridge;    
    }
    key_mas[i * 2 + 2] = key_res1;
    key_mas[i * 2 + 3] = key_res2;
    }

    for _i in 0..10{
        //println!("{:x}", key_mas[i]);
    }
}

fn block_replace_encrip(num: &u128) -> u128{
    let mut arr = [0u8; 16];
    for i in 0..16 {
        arr[i] = ((num >> ((15 - i) * 8)) & 0xFF) as u8;
    }
    
    for i in 0..16{
        arr[i] = S_BOX[arr[i] as usize];
    }

    let mut res:u128 = 0;
    // Склеивание чисел
    for i in 0..16 {
        res |= (arr[i] as u128) << ((15 - i) * 8);
    }

    res
}

// fn block_replace_decrip(num: &u128) -> u128{
//     let mut arr = [0u8; 16];
//     for i in 0..16 {
//         arr[i] = ((num >> ((15 - i) * 8)) & 0xFF) as u8;
//     }
//     for i in 0..16{
//         for j in 0..256{
//             if arr [i] == S_BOX[j]{ 
//                 arr[i] = j as u8;
//                 break;
//             }
//         }
//     }
//     let mut res:u128 = 0;
//     // Склеивание чисел
//     for i in 0..16 {
//         res |= (arr[i] as u128) << ((15 - i) * 8);
//     }
//     res
// }

fn lin_pr(num: &u128) -> u8{
    let mut a = [0u8; 16];
    let coef:[u8; 16] = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1];

    for i in 0..16{
        a[i] = ((num >> i*8) & 0xFF) as u8;
    }

    let mut result:u8 = 0;
    for i in 0..16{
        result ^= gf_to_bin(gf_mult(&bin_to_gf(&(a[15 - i])), &bin_to_gf(&(coef[i]))));
    }

    result
}

fn interfere_blocks_encrip(num: &mut u128) -> u128{
    for _i in 0..16{
        *num = r_move_en(num);
    }
    *num
}

// fn interfere_blocks_decrip(num: &mut u128) -> u128{
//     for _i in 0..16{
//         *num = r_move_dec(num);
//     }
//     *num
// }

fn r_move_en(num: &mut u128) -> u128{
    let mut arr = [0u8; 16];
    for i in 0..16 {
        arr[i] = ((*num >> ((15 - i) * 8)) & 0xFF) as u8;
    }

    for i in 0..15{
    arr[15 - i] = arr[14 - i]; 
    }
    arr[0] = lin_pr(&num);
    
    *num = 0;
    for i in 0..16 {
        *num |= (arr[i] as u128) << ((15 - i) * 8);
    }

    *num
}

// fn r_move_dec(num: &mut u128) -> u128{
//     let mut pre_res = num.clone();
//
//     // Извлекаем первые 8 бит
//     let first_8_bits = (pre_res >> 120) & 0xFF;
//
//     // Сдвигаем число влево на 8 бит, чтобы удалить первые 8 бит
//     pre_res <<= 8;
//
//     // Добавляем первые 8 бит в конец числа
//     pre_res |= first_8_bits;
//
//     let lin_res = lin_pr(&pre_res);
//
//     *num <<= 8;
//
//     *num |= lin_res as u128;
//    
//
//     *num
// }


fn gf_mult(m_n1: &[bool; 128], m_n2: &[bool;128]) -> [bool; 256]{
    let mut m_res = [false; 256];

    for i in 0..128{
        for j in 0..128{
            if (m_n1[i] == true) && (m_n2[j] == true){
                if m_res[i+j] == true{
                    m_res[i+j] = false;
                }
                else{m_res[i+j] = true;}
            }
        }
    }
    
    for i in 0..248{
        if m_res[255 - i] == false{
            continue;
        }
        m_res[255 - i] = bool_add(POL[0], m_res[255 - i]);
        m_res[254 - i] = bool_add(POL[1], m_res[254 - i]);
        m_res[253 - i] = bool_add(POL[2], m_res[253 - i]);
        m_res[252 - i] = bool_add(POL[3], m_res[252 - i]);
        m_res[251 - i] = bool_add(POL[4], m_res[251 - i]);
        m_res[250 - i] = bool_add(POL[5], m_res[250 - i]);
        m_res[249 - i] = bool_add(POL[6], m_res[249 - i]);
        m_res[248 - i] = bool_add(POL[7], m_res[248 - i]);
        m_res[247 - i] = bool_add(POL[8], m_res[247 - i]);
    }

    m_res 
}

fn bool_add(a: bool, b: bool) -> bool {
    match (a, b) {
        (true, true) => false,
        (true, false) => true,
        (false, true) => true,
        (false, false) => false,
    }
}

fn bin_to_gf(num: &u8) -> [bool; 128]{
    let mut m_num = [false; 128];

    // Преобразование num в массив битов
    for i in 0..8 {
        m_num[i] = (num & (1 << i)) != 0;
    }

    m_num
}

fn gf_to_bin(m_num: [bool; 256]) -> u8{
    let mut num: u8 = 0;

    for i in 0..8 {
        if m_num[i] {
            num = num | (1 << i);
        }
    }

    num
}