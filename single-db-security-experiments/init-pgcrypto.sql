-- 启用 pgcrypto 扩展
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 创建带加密功能的辅助函数
-- 使用 AES-256 加密
CREATE OR REPLACE FUNCTION encrypt_text(plain_text TEXT, key_text TEXT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(plain_text, key_text, 'cipher-algo=aes256');
END;
$$ LANGUAGE plpgsql;

-- 解密函数
CREATE OR REPLACE FUNCTION decrypt_text(encrypted_data BYTEA, key_text TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(encrypted_data, key_text);
END;
$$ LANGUAGE plpgsql;

-- 验证安装成功
SELECT 'pgcrypto extension installed successfully' AS status;
