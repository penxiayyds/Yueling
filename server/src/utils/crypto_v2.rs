use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Sha256, Sha512, Digest};
use serde::{Serialize, Deserialize};
use hex;
use std::error::Error;
use base64;

const BLOCK_SIZE: usize = 16; // 字节

/// 加密元数据，用于记录多层防御加密的信息
#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    /// 原始明文长度
    original_len: usize,
    /// 第一层：真实块的排列顺序，每个元素是原始块索引
    permutation: Vec<usize>,
    /// 第二层：填充块的位置（在最终块列表中的索引）
    padding_positions: Vec<usize>,
    /// 第三层：XOR混淆密钥的哈希值
    xor_key_hash: String,
    /// 第四层：块交换的映射表
    block_swap_map: Vec<(usize, usize)>,
    /// 第五层：块内字节移位模式
    byte_shift_patterns: Vec<u8>,
    /// 第六层：时间戳盐值
    timestamp_salt: u64,
    /// 第七层：块内比特翻转模式
    bit_flip_patterns: Vec<u8>,
    /// 第八层：子块混洗参数
    subblock_shuffle_seed: [u8; 32],
    /// 第九层：最终编码参数
    final_encoding_params: (u8, u8), // (base变体, 附加轮次)
}

/// 加密服务，持有私钥并提供加密/解密功能
#[derive(Clone)]
pub struct CryptoService {
    /// 私钥，32字节，用于AES-256-GCM加密
    private_key: [u8; 32],
    /// 防御层配置
    defense_config: DefenseConfig,
}

/// 防御层配置
#[derive(Clone)]
struct DefenseConfig {
    /// 是否启用所有防御层
    enable_all_layers: bool,
    /// 每个防御层的启用状态
    layer_enabled: [bool; 9],
    /// 自定义参数
    custom_params: std::collections::HashMap<String, Vec<u8>>,
}

impl CryptoService {
    /// 生成一个新的随机私钥
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        // 初始化默认防御配置（启用所有层）
        let defense_config = DefenseConfig {
            enable_all_layers: true,
            layer_enabled: [true; 9], // 默认启用所有9层防御
            custom_params: std::collections::HashMap::new(),
        };

        CryptoService {
            private_key: key,
            defense_config,
        }
    }

    /// 从已有的私钥字节构造（例如从环境变量或配置文件读取）
    pub fn from_key(private_key: [u8; 32]) -> Self {
        let defense_config = DefenseConfig {
            enable_all_layers: true,
            layer_enabled: [true; 9], // 默认启用所有9层防御
            custom_params: std::collections::HashMap::new(),
        };

        CryptoService {
            private_key,
            defense_config,
        }
    }

    /// 从十六进制字符串加载私钥
    pub fn from_hex(hex_key: &str) -> Result<Self, Box<dyn Error>> {
        let bytes = hex::decode(hex_key)?;
        if bytes.len() != 32 {
            return Err("私钥长度必须为32字节".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);

        let defense_config = DefenseConfig {
            enable_all_layers: true,
            layer_enabled: [true; 9], // 默认启用所有9层防御
            custom_params: std::collections::HashMap::new(),
        };

        Ok(CryptoService {
            private_key: key,
            defense_config,
        })
    }

    /// 获取私钥的十六进制表示（用于存储或调试）
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// 使用私钥派生一个确定性RNG
    fn derive_rng(&self) -> ChaCha20Rng {
        let mut hasher = Sha256::new();
        hasher.update(b"deterministic-rng-seed");
        hasher.update(&self.private_key);
        let seed: [u8; 32] = hasher.finalize().into();
        ChaCha20Rng::from_seed(seed)
    }

    /// 派生密钥流（用于私有算法）
    fn derive_keystream(&self, length: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(length);
        let mut hasher = Sha256::new();
        hasher.update(b"private-algorithm-keystream");
        hasher.update(&self.private_key);
        let mut seed = hasher.finalize();
        while keystream.len() < length {
            keystream.extend_from_slice(&seed);
            let mut hasher = Sha256::new();
            hasher.update(&seed);
            seed = hasher.finalize();
        }
        keystream.truncate(length);
        keystream
    }

    /// 私有算法加密（XOR混淆）
    fn private_encrypt(&self, data: &[u8]) -> Vec<u8> {
        let keystream = self.derive_keystream(data.len());
        data.iter().zip(keystream).map(|(d, k)| d ^ k).collect()
    }

    /// 私有算法解密（XOR混淆，与加密相同）
    fn private_decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.private_encrypt(data)
    }

    // ===== 防御层方法 =====

    /// 第一层：增强XOR混淆
    fn enhanced_xor_encrypt(&self, data: &[u8], metadata: &mut Metadata) -> Vec<u8> {
        if !self.defense_config.layer_enabled[0] {
            return data.to_vec();
        }

        // 生成基于私钥和随机盐的XOR密钥
        let mut rng = self.derive_rng();
        let mut xor_key = [0u8; 32];
        rng.fill_bytes(&mut xor_key);

        // 计算密钥哈希并存储到元数据
        let mut hasher = Sha256::new();
        hasher.update(&xor_key);
        metadata.xor_key_hash = hex::encode(hasher.finalize());

        // 应用XOR混淆
        let mut result = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ xor_key[i % xor_key.len()]);
        }

        result
    }

    /// 第一层：增强XOR解密
    fn enhanced_xor_decrypt(&self, data: &[u8], metadata: &Metadata) -> Vec<u8> {
        if !self.defense_config.layer_enabled[0] {
            return data.to_vec();
        }

        // 从哈希重建XOR密钥
        let key_hash_bytes = hex::decode(&metadata.xor_key_hash).unwrap();
        // 注意：这里简化处理，实际应用中可能需要更复杂的密钥恢复机制
        let mut hasher = Sha256::new();
        hasher.update(&self.private_key);
        hasher.update(&key_hash_bytes);
        let xor_key = hasher.finalize();

        // 应用XOR解密
        let mut result = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ xor_key[i % xor_key.len()]);
        }

        result
    }

    /// 第二层：块交换加密
    fn block_swap_encrypt(&self, blocks: &mut [Vec<u8>], metadata: &mut Metadata) {
        if !self.defense_config.layer_enabled[1] || blocks.is_empty() {
            return;
        }

        let mut rng = self.derive_rng();
        let num_swaps = (blocks.len() / 3).max(1); // 确保至少有一次交换

        for _ in 0..num_swaps {
            let i = (rng.next_u32() as usize) % blocks.len();
            let j = (rng.next_u32() as usize) % blocks.len();

            if i != j {
                blocks.swap(i, j);
                metadata.block_swap_map.push((i, j));
            }
        }
    }

    /// 第二层：块交换解密
    fn block_swap_decrypt(&self, blocks: &mut [Vec<u8>], metadata: &Metadata) {
        if !self.defense_config.layer_enabled[1] || metadata.block_swap_map.is_empty() {
            return;
        }

        // 逆序执行交换操作以恢复原始顺序
        for &(i, j) in metadata.block_swap_map.iter().rev() {
            if i < blocks.len() && j < blocks.len() {
                blocks.swap(i, j);
            }
        }
    }

    /// 第三层：字节移位加密
    fn byte_shift_encrypt(&self, blocks: &mut [Vec<u8>], metadata: &mut Metadata) {
        if !self.defense_config.layer_enabled[2] || blocks.is_empty() {
            return;
        }

        let mut rng = self.derive_rng();

        for block in blocks.iter_mut() {
            // 为每个块生成一个随机移位模式 (0-7)
            let shift_pattern = (rng.next_u32() % 8) as u8;
            metadata.byte_shift_patterns.push(shift_pattern);

            // 应用循环左移位
            if shift_pattern > 0 && !block.is_empty() {
                let shift = (shift_pattern % 8) as u32;
                for byte in block.iter_mut() {
                    *byte = byte.rotate_left(shift);
                }
            }
        }
    }

    /// 第三层：字节移位解密
    fn byte_shift_decrypt(&self, blocks: &mut [Vec<u8>], metadata: &Metadata) {
        if !self.defense_config.layer_enabled[2] || metadata.byte_shift_patterns.is_empty() {
            return;
        }

        for (i, block) in blocks.iter_mut().enumerate() {
            if i < metadata.byte_shift_patterns.len() {
                let shift_pattern = metadata.byte_shift_patterns[i];
                // 应用反向操作：循环右移位
                if shift_pattern > 0 && !block.is_empty() {
                    let shift = (shift_pattern % 8) as u32;
                    for byte in block.iter_mut() {
                        *byte = byte.rotate_right(shift);
                    }
                }
            }
        }
    }

    /// 第四层：时间戳盐值加密
    fn timestamp_salt_encrypt(&self, data: &[u8], metadata: &mut Metadata) -> Vec<u8> {
        if !self.defense_config.layer_enabled[3] {
            return data.to_vec();
        }

        // 生成当前时间戳作为盐值
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 存储时间戳到元数据
        metadata.timestamp_salt = timestamp;

        // 将时间戳转换为字节数组
        let timestamp_bytes = timestamp.to_be_bytes();

        // 使用时间戳作为盐值，与私钥结合生成新的密钥
        let mut hasher = Sha512::new();
        hasher.update(&self.private_key);
        hasher.update(&timestamp_bytes);
        let salted_key = hasher.finalize();

        // 使用盐化密钥进行XOR加密
        let mut result = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ salted_key[i % salted_key.len()]);
        }

        result
    }

    /// 第四层：时间戳盐值解密
    fn timestamp_salt_decrypt(&self, data: &[u8], metadata: &Metadata) -> Vec<u8> {
        if !self.defense_config.layer_enabled[3] {
            return data.to_vec();
        }

        // 从元数据中获取时间戳
        let timestamp = metadata.timestamp_salt;
        let timestamp_bytes = timestamp.to_be_bytes();

        // 重新生成盐化密钥
        let mut hasher = Sha512::new();
        hasher.update(&self.private_key);
        hasher.update(&timestamp_bytes);
        let salted_key = hasher.finalize();

        // 使用盐化密钥进行XOR解密
        let mut result = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ salted_key[i % salted_key.len()]);
        }

        result
    }

    /// 第五层：比特翻转加密
    fn bit_flip_encrypt(&self, blocks: &mut [Vec<u8>], metadata: &mut Metadata) {
        if !self.defense_config.layer_enabled[4] || blocks.is_empty() {
            return;
        }

        let mut rng = self.derive_rng();

        for block in blocks.iter_mut() {
            // 为每个块生成一个随机比特翻转模式 (0-7)
            let flip_pattern = (rng.next_u32() % 8) as u8;
            metadata.bit_flip_patterns.push(flip_pattern);

            // 应用比特翻转
            if flip_pattern > 0 && !block.is_empty() {
                for byte in block.iter_mut() {
                    // 根据模式翻转特定的比特位
                    for bit_pos in 0..8 {
                        if (flip_pattern >> bit_pos) & 1 == 1 {
                            *byte ^= 1 << bit_pos;
                        }
                    }
                }
            }
        }
    }

    /// 第五层：比特翻转解密
    fn bit_flip_decrypt(&self, blocks: &mut [Vec<u8>], metadata: &Metadata) {
        if !self.defense_config.layer_enabled[4] || metadata.bit_flip_patterns.is_empty() {
            return;
        }

        for (i, block) in blocks.iter_mut().enumerate() {
            if i < metadata.bit_flip_patterns.len() {
                let flip_pattern = metadata.bit_flip_patterns[i];
                // 应用相同的比特翻转（XOR操作是自反的）
                if flip_pattern > 0 && !block.is_empty() {
                    for byte in block.iter_mut() {
                        // 根据模式翻转相同的比特位
                        for bit_pos in 0..8 {
                            if (flip_pattern >> bit_pos) & 1 == 1 {
                                *byte ^= 1 << bit_pos;
                            }
                        }
                    }
                }
            }
        }
    }

    /// 第六层：子块混洗加密
    fn subblock_shuffle_encrypt(&self, blocks: &mut [Vec<u8>], metadata: &mut Metadata) {
        if !self.defense_config.layer_enabled[5] || blocks.is_empty() {
            return;
        }

        // 生成子块混洗种子
        let mut rng = self.derive_rng();
        rng.fill_bytes(&mut metadata.subblock_shuffle_seed);
        let mut subblock_rng = ChaCha20Rng::from_seed(metadata.subblock_shuffle_seed);

        // 每个块分成4个子块，然后混洗
        for block in blocks.iter_mut() {
            if block.len() < 4 {
                continue; // 块太小，跳过
            }

            // 计算子块大小
            let subblock_size = block.len() / 4;
            let remainder = block.len() % 4;

            // 分割成子块
            let mut subblocks = Vec::with_capacity(4);
            let mut start = 0;
            for i in 0..4 {
                let size = if i < 3 { subblock_size } else { subblock_size + remainder };
                let end = start + size;
                subblocks.push(block[start..end].to_vec());
                start = end;
            }

            // 生成随机排列并应用
            let mut perm: Vec<usize> = (0..4).collect();
            for i in (1..4).rev() {
                let j = (subblock_rng.next_u32() as usize) % (i + 1);
                perm.swap(i, j);
            }

            // 重新组装块
            let mut new_block = Vec::with_capacity(block.len());
            for &idx in &perm {
                new_block.extend_from_slice(&subblocks[idx]);
            }
            *block = new_block;
        }
    }

    /// 第六层：子块混洗解密
    fn subblock_shuffle_decrypt(&self, blocks: &mut [Vec<u8>], metadata: &Metadata) {
        if !self.defense_config.layer_enabled[5] || blocks.is_empty() {
            return;
        }

        // 使用相同的种子重新生成RNG
        let subblock_rng = ChaCha20Rng::from_seed(metadata.subblock_shuffle_seed);

        // 为每个块恢复原始顺序
        for block in blocks.iter_mut() {
            if block.len() < 4 {
                continue; // 块太小，跳过
            }

            // 计算子块大小
            let subblock_size = block.len() / 4;
            let remainder = block.len() % 4;

            // 分割成子块
            let mut subblocks = Vec::with_capacity(4);
            let mut start = 0;
            for i in 0..4 {
                let size = if i < 3 { subblock_size } else { subblock_size + remainder };
                let end = start + size;
                subblocks.push(block[start..end].to_vec());
                start = end;
            }

            // 重新生成相同的随机排列
            let mut perm: Vec<usize> = (0..4).collect();
            let mut temp_rng = subblock_rng.clone();
            for i in (1..4).rev() {
                let j = (temp_rng.next_u32() as usize) % (i + 1);
                perm.swap(i, j);
            }

            // 创建反向映射
            let mut reverse_perm = vec![0; 4];
            for (i, &pos) in perm.iter().enumerate() {
                reverse_perm[pos] = i;
            }

            // 重新组装块为原始顺序
            let mut new_block = Vec::with_capacity(block.len());
            for &idx in &reverse_perm {
                new_block.extend_from_slice(&subblocks[idx]);
            }
            *block = new_block;
        }
    }

    /// 第七层：最终编码加密
    fn final_encoding_encrypt(&self, data: &[u8], metadata: &mut Metadata) -> String {
        if !self.defense_config.layer_enabled[6] {
            // 如果未启用，直接返回Base64编码
            return base64::encode(data);
        }

        let mut rng = self.derive_rng();

        // 生成编码参数
        let base_variant = (rng.next_u32() % 3) as u8; // 0: Base64, 1: Base32, 2: Base16
        let extra_rounds = (rng.next_u32() % 3) as u8 + 1; // 1-3轮额外编码
        metadata.final_encoding_params = (base_variant, extra_rounds);

        // 应用多轮编码
        let mut encoded = match base_variant {
            0 => base64::encode(data),
            1 => self.base32_encode(data),
            _ => hex::encode(data),
        };

        // 额外编码轮次
        for _ in 0..extra_rounds {
            encoded = match (rng.next_u32() % 3) as u8 {
                0 => base64::encode(encoded.as_bytes()),
                1 => self.base32_encode(encoded.as_bytes()),
                _ => hex::encode(encoded.as_bytes()),
            };
        }

        encoded
    }

    /// 第七层：最终编码解密
    fn final_encoding_decrypt(&self, encoded: &str, metadata: &Metadata) -> Result<Vec<u8>, Box<dyn Error>> {
        if !self.defense_config.layer_enabled[6] {
            // 如果未启用，直接返回Base64解码
            return Ok(base64::decode(encoded)?);
        }

        let (base_variant, extra_rounds) = metadata.final_encoding_params;

        // 逆向解码过程
        let mut decoded = encoded.to_string();

        // 反向额外编码轮次
        let mut rng = self.derive_rng();
        // 需要重新生成相同的随机序列来确定解码顺序
        for _ in 0..extra_rounds {
            let variant = (rng.next_u32() % 3) as u8;
            decoded = match variant {
                0 => String::from_utf8(base64::decode(&decoded)?)?,
                1 => String::from_utf8(self.base32_decode(&decoded)?)?,
                _ => String::from_utf8(hex::decode(&decoded)?)?,
            };
        }

        // 最后解码
        let result = match base_variant {
            0 => base64::decode(&decoded)?,
            1 => self.base32_decode(&decoded)?,
            _ => hex::decode(&decoded)?,
        };

        Ok(result)
    }

    /// Base32编码实现
    fn base32_encode(&self, data: &[u8]) -> String {
        // 简化的Base32实现
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = String::new();

        // 处理5字节块
        let mut i = 0;
        while i < data.len() {
            let mut block = [0u8; 5];
            let block_size = std::cmp::min(5, data.len() - i);
            block[..block_size].copy_from_slice(&data[i..i+block_size]);

            // 转换为8个5位值
            let mut bits = 0u64;
            for (j, &byte) in block.iter().enumerate() {
                bits |= (byte as u64) << (8 * (4 - j));
            }

            for j in 0..8 {
                if j * 5 < block_size * 8 {
                    let idx = ((bits >> (35 - j * 5)) & 0x1F) as usize;
                    result.push(ALPHABET[idx] as char);
                } else {
                    result.push('='); // 填充
                }
            }

            i += 5;
        }

        result
    }

    /// Base32解码实现
    fn base32_decode(&self, encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        // 简化的Base32解码实现
        let mut result = Vec::new();
        let mut bits = 0u64;
        let mut bits_count = 0;

        for c in encoded.chars() {
            if c == '=' {
                break; // 遇到填充停止
            }

            let value = match c {
                'A'..='Z' => c as u8 - b'A',
                '2'..='7' => c as u8 - b'2' + 26,
                _ => return Err("无效的Base32字符".into()),
            };

            bits = (bits << 5) | value as u64;
            bits_count += 5;

            if bits_count >= 8 {
                result.push((bits >> (bits_count - 8)) as u8);
                bits_count -= 8;
            }
        }

        Ok(result)
    }

    /// 核心加密函数：9层防御加密
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // 初始化元数据
        let mut metadata = Metadata {
            original_len: plaintext.len(),
            permutation: Vec::new(),
            padding_positions: Vec::new(),
            xor_key_hash: String::new(),
            block_swap_map: Vec::new(),
            byte_shift_patterns: Vec::new(),
            timestamp_salt: 0,
            bit_flip_patterns: Vec::new(),
            subblock_shuffle_seed: [0u8; 32],
            final_encoding_params: (0, 0),
        };

        // 第一层：增强XOR混淆
        let mut encrypted_data = self.enhanced_xor_encrypt(plaintext, &mut metadata);

        // 第二层：时间戳盐值加密
        encrypted_data = self.timestamp_salt_encrypt(&encrypted_data, &mut metadata);

        // 第三层：私有算法加密（XOR混淆）
        encrypted_data = self.private_encrypt(&encrypted_data);

        // 第四层：AES-GCM加密
        encrypted_data = self.aes_encrypt(&encrypted_data)?;

        // 第五层：拆分与块操作
        let mut blocks = Self::split_into_blocks(&encrypted_data, BLOCK_SIZE);

        // 第六层：块交换
        self.block_swap_encrypt(&mut blocks, &mut metadata);

        // 第七层：字节移位
        self.byte_shift_encrypt(&mut blocks, &mut metadata);

        // 第八层：比特翻转
        self.bit_flip_encrypt(&mut blocks, &mut metadata);

        // 子块混洗
        self.subblock_shuffle_encrypt(&mut blocks, &mut metadata);

        // 原始换序与填充
        let mut rng = self.derive_rng();
        metadata.permutation = Self::generate_permutation(blocks.len(), &mut rng);
        let shuffled = Self::apply_permutation(&blocks, &metadata.permutation);
        let (padded_blocks, padding_positions) = Self::add_padding(shuffled, &mut rng);
        metadata.padding_positions = padding_positions;

        // 加密元数据
        let metadata_bytes = serde_json::to_vec(&metadata)?;
        let encrypted_metadata = self.aes_encrypt(&metadata_bytes)?;

        // 合并：加密的元数据长度（2字节） + 加密的元数据 + 混淆后的块数据
        let mut result = Vec::new();
        if encrypted_metadata.len() > 65535 {
            return Err("元数据过长".into());
        }
        result.push((encrypted_metadata.len() >> 8) as u8);
        result.push((encrypted_metadata.len() & 0xFF) as u8);
        result.extend_from_slice(&encrypted_metadata);
        for block in padded_blocks {
            result.extend_from_slice(&block);
        }

        // 第九层：最终编码
        let encoded = self.final_encoding_encrypt(&result, &mut metadata);
        Ok(encoded.into_bytes())
    }

    /// 核心解密函数：9层防御解密
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // 将数据转换为字符串以进行最终解码
        let encoded_str = String::from_utf8(data.to_vec())?;
        
        // 初始化元数据（用于解码）
        let mut temp_metadata = Metadata {
            original_len: 0,
            permutation: Vec::new(),
            padding_positions: Vec::new(),
            xor_key_hash: String::new(),
            block_swap_map: Vec::new(),
            byte_shift_patterns: Vec::new(),
            timestamp_salt: 0,
            bit_flip_patterns: Vec::new(),
            subblock_shuffle_seed: [0u8; 32],
            final_encoding_params: (0, 0),
        };
        
        // 第九层：最终编码解密
        let decoded = self.final_encoding_decrypt(&encoded_str, &temp_metadata)?;
        
        // 1. 提取元数据长度
        if decoded.len() < 2 {
            return Err("数据过短".into());
        }
        let metadata_len = ((decoded[0] as usize) << 8) | (decoded[1] as usize);
        let metadata_start = 2;
        let metadata_end = metadata_start + metadata_len;
        if metadata_end > decoded.len() {
            return Err("元数据长度超出数据范围".into());
        }
        let encrypted_metadata = &decoded[metadata_start..metadata_end];
        let blocks_data = &decoded[metadata_end..];
        
        // 2. 解密元数据
        let metadata_bytes = self.aes_decrypt(encrypted_metadata)?;
        let metadata: Metadata = serde_json::from_slice(&metadata_bytes)?;
        
        // 3. 将块数据分割成块
        let block_count = blocks_data.len() / BLOCK_SIZE;
        if block_count * BLOCK_SIZE != blocks_data.len() {
            return Err("块数据长度不是块大小的整数倍".into());
        }
        let mut blocks = Vec::with_capacity(block_count);
        for i in 0..block_count {
            let start = i * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            blocks.push(blocks_data[start..end].to_vec());
        }
        
        // 4. 移除填充块
        let unpadded = Self::remove_padding(blocks, &metadata.padding_positions)?;
        
        // 5. 恢复原始顺序
        let mut unshuffled = Self::reverse_permutation(unpadded, &metadata.permutation)?;
        
        // 6. 子块混洗解密
        self.subblock_shuffle_decrypt(&mut unshuffled, &metadata);
        
        // 7. 比特翻转解密
        self.bit_flip_decrypt(&mut unshuffled, &metadata);
        
        // 8. 字节移位解密
        self.byte_shift_decrypt(&mut unshuffled, &metadata);
        
        // 9. 块交换解密
        self.block_swap_decrypt(&mut unshuffled, &metadata);
        
        // 10. 合并块并截断到原始长度
        let mut ciphertext = Self::merge_blocks(unshuffled, BLOCK_SIZE);
        
        // 11. AES-GCM解密
        let aes_decrypted = self.aes_decrypt(&ciphertext)?;
        
        // 12. 私有算法解密
        let private_decrypted = self.private_decrypt(&aes_decrypted);
        
        // 13. 时间戳盐值解密
        let timestamp_decrypted = self.timestamp_salt_decrypt(&private_decrypted, &metadata);
        
        // 14. 增强XOR解密
        Ok(self.enhanced_xor_decrypt(&timestamp_decrypted, &metadata))
    }

    /// AES-GCM加密（使用私钥作为密钥）
    fn aes_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let key = Key::<Aes256Gcm>::from_slice(&self.private_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 随机nonce
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("AES加密失败: {}", e))?;
        // 将nonce和密文拼接（nonce长度固定为12字节）
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// AES-GCM解密
    fn aes_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if data.len() < 12 {
            return Err("数据过短，缺少nonce".into());
        }
        let (nonce_slice, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_slice);
        let key = Key::<Aes256Gcm>::from_slice(&self.private_key);
        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES解密失败: {}", e))?;
        Ok(plaintext)
    }

    /// 将字节切片拆分成固定大小的块，最后一块不足则补零
    fn split_into_blocks(data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
        let mut blocks = Vec::new();
        for chunk in data.chunks(block_size) {
            let mut block = chunk.to_vec();
            if block.len() < block_size {
                block.resize(block_size, 0); // 补零填充
            }
            blocks.push(block);
        }
        blocks
    }

    /// 合并块，并去除尾部可能多余的零（需要原始长度信息）
    fn merge_blocks(blocks: Vec<Vec<u8>>, block_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(blocks.len() * block_size);
        for block in blocks {
            result.extend_from_slice(&block);
        }
        result
    }

    /// 生成一个随机排列
    fn generate_permutation(len: usize, rng: &mut ChaCha20Rng) -> Vec<usize> {
        let mut perm: Vec<usize> = (0..len).collect();
        for i in (1..len).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            perm.swap(i, j);
        }
        perm
    }

    /// 应用排列
    fn apply_permutation(blocks: &[Vec<u8>], permutation: &[usize]) -> Vec<Vec<u8>> {
        let mut shuffled = Vec::with_capacity(blocks.len());
        for &idx in permutation {
            shuffled.push(blocks[idx].clone());
        }
        shuffled
    }

    /// 反转排列
    fn reverse_permutation(mut blocks: Vec<Vec<u8>>, permutation: &[usize]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        if blocks.len() != permutation.len() {
            return Err("块数量与排列长度不匹配".into());
        }
        let mut restored = vec![Vec::new(); blocks.len()];
        for (i, &pos) in permutation.iter().enumerate() {
            if pos >= blocks.len() {
                return Err("排列索引越界".into());
            }
            std::mem::swap(&mut restored[pos], &mut blocks[i]);
        }
        Ok(restored)
    }

    /// 添加填充块：在随机位置插入随机块
    fn add_padding(mut blocks: Vec<Vec<u8>>, rng: &mut ChaCha20Rng) -> (Vec<Vec<u8>>, Vec<usize>) {
        let mut padding_positions = Vec::new();
        let mut i = 0;
        while i < blocks.len() {
            // 以1/3的概率在当前位置之前插入一个填充块
            if rng.next_u32() % 3 == 0 {
                let mut pad = vec![0u8; BLOCK_SIZE];
                rng.fill_bytes(&mut pad);
                blocks.insert(i, pad);
                padding_positions.push(i);
                i += 1; // 跳过刚插入的块
            }
            i += 1;
        }
        (blocks, padding_positions)
    }

    /// 移除填充块
    fn remove_padding(mut blocks: Vec<Vec<u8>>, padding_positions: &[usize]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        // 按降序排序位置，以便从后向前移除，避免索引变化
        let mut sorted_positions = padding_positions.to_vec();
        sorted_positions.sort_by(|a, b| b.cmp(a));
        for &pos in &sorted_positions {
            if pos >= blocks.len() {
                return Err("填充位置越界".into());
            }
            blocks.remove(pos);
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation() {
        let service = CryptoService::generate();
        let hex_key = service.private_key_hex();
        assert_eq!(hex_key.len(), 64); // 32字节 = 64十六进制字符
    }

    #[test]
    fn test_from_hex() {
        let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let service = CryptoService::from_hex(key_hex).unwrap();
        assert_eq!(service.private_key_hex(), key_hex);
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let service = CryptoService::generate();
        let plaintext = b"Hello, world!";
        let ciphertext = service.aes_encrypt(plaintext).unwrap();
        let decrypted = service.aes_decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_full_encrypt_decrypt() {
        let service = CryptoService::generate();
        let plaintext = b"This is a secret message that needs encryption.";
        let encrypted = service.encrypt(plaintext).unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys() {
        let service1 = CryptoService::generate();
        let service2 = CryptoService::generate();
        let plaintext = b"Test";
        let encrypted = service1.encrypt(plaintext).unwrap();
        // 使用不同的密钥解密应该失败或得到错误结果
        let result = service2.decrypt(&encrypted);
        assert!(result.is_err());
    }
}
