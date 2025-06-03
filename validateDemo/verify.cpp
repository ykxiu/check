//
//  verify.cpp
//  main
//
//  Created by liaddan on 2025/3/27.
//

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <unordered_map>
#include <pcapplusplus/Packet.h>

struct HMACResult
{
    unsigned char digest[32];
    unsigned int digest_length;
};

// 检查 OpenSSL 错误
void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// 打印二进制数据
void print_binary(const unsigned char *data, int length)
{

    for (int i = 0; i < length; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
}

std::string calculateMD5(const char *input)
{
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    // 获取字符数组的长度，假设字符数组以'\0'结尾
    size_t len = 0;
    while (input[len] != '\0')
    {
        len++;
    }
    MD5_Update(&md5Context, input, len);
    MD5_Final(hash, &md5Context);
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// 将 32 位无符号整数转换为时间戳并输出
void convertToTimestamp(uint32_t timestampValue)
{
    time_t timestamp = static_cast<time_t>(timestampValue);
    tm *timeInfo = localtime(&timestamp);

    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeInfo);
    std::cout << "转换后的时间戳: " << buffer << std::endl;
}

// 从文件读取私钥
EVP_PKEY *read_private_key(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("无法打开私钥文件");
        handleErrors();
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!pkey)
    {
        fprintf(stderr, "无法读取私钥\n");
        handleErrors();
    }
    return pkey;
}

// 从文件读取私钥
EVP_PKEY *read_public_key(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("无法打开公钥文件");
        handleErrors();
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!pkey)
    {
        fprintf(stderr, "无法读取公钥\n");
        handleErrors();
    }
    return pkey;
}

const uint8_t *find_start_ptr(const uint8_t *data, size_t length)
{
    const uint32_t pattern = 0x1acffc1d;
    for (size_t i = 0; i <= length - 4; ++i)
    {
        uint32_t current = static_cast<uint32_t>(data[i]) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                           (static_cast<uint32_t>(data[i + 2]) << 16) |
                           (static_cast<uint32_t>(data[i + 3]) << 24);
        if (current == pattern)
        {
            return data + i;
        }
    }
    return nullptr;
}

const uint8_t *find_end_ptr(const uint8_t *data, size_t length)
{
    const uint32_t pattern = 0x1acffc1e;
    for (size_t i = 0; i <= length - 4; ++i)
    {
        uint32_t current = static_cast<uint32_t>(data[i]) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                           (static_cast<uint32_t>(data[i + 2]) << 16) |
                           (static_cast<uint32_t>(data[i + 3]) << 24);
        if (current == pattern)
        {
            return data + i;
        }
    }
    return nullptr;
}

HMACResult gen_hmac(int id, char data[])
{
    std::unordered_map<int, std::string> satelliteMap;
    satelliteMap[7] = "c449450ddfb3d5eb6261ed3a34722902abf3fd99dd9105286d843d37ce4e4b6f";
    // 访问字典中的值

    unsigned char digest[32];
    unsigned int digest_length = 32;
    auto it = satelliteMap.find(id);
    if (it != satelliteMap.end())
    {
        const int key_length = 32; // 密钥长度，对于 SHA-256 通常为 32 字节

        // 1. 获取密钥
        unsigned char key[key_length];
        std::strncpy(reinterpret_cast<char *>(key), it->second.c_str(), key_length);
        key[key_length - 1] = '\0'; // 确保以'\0'结尾

        // 2. 生成md5
        std::string md5_message = calculateMD5(data);
        const unsigned char *md5_message_data = reinterpret_cast<const unsigned char *>(md5_message.c_str());
        int md5_message_length = static_cast<int>(md5_message.size());

        // 3. 生成密文
        // FIXME:// 必现的crash？？？？？
        //        hmac_encrypt(key, key_length, md5_message_data, md5_message_length, digest, &digest_length);

        // 打印密文
        // std::cout << "生成的密文: ";
        // print_binary(md5_message_data, md5_message_length);

        // 打印密文的比特大小
        // std::cout << "密文的比特大小: " << digest_length * 8 << " bits" << std::endl;
        HMACResult result;
        //        for(int i = 0; i < 32 ; i ++ ) {
        //            result.digest[i] = digest[i];
        //        }
        //        result.digest[digest_length - 1] = '\0';  // 确保以'\0'结尾
        std::memcpy(result.digest, md5_message_data, md5_message_length);
        return result;
    }
    else
    {
        std::cout << "未找到对应的卫星ID" << std::endl;
    }

    return HMACResult();
}

// 使用公钥验证签名
bool verifySignature(EVP_PKEY *pubKey, const unsigned char message[], const unsigned char *signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t signatureLen = 256;
    if (!ctx)
    {
        handleErrors();
    }

    if (!EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubKey))
    {
        handleErrors();
    }

    if (!EVP_DigestVerifyUpdate(ctx, message, signatureLen))
    {
        handleErrors();
    }

    int result = EVP_DigestVerifyFinal(ctx, signature, signatureLen);
    EVP_MD_CTX_free(ctx);

    if (result == -1)
    {
        handleErrors();
    }

    return result == 1;
}

bool verify_timestamp(const uint8_t *data, size_t length)
{
    // 跳过 0x1ACFFC1D 以及后面一个字节(卫星号)
    const uint8_t *timestampPtr = data + 4 + 1;
    if (timestampPtr == nullptr)
    {
        // 这里可以使用 /timestampPtr 进行后续操作
        std::cout << "timestamp 为空" << timestampPtr << std::endl;
    }
    if (timestampPtr + 3 < data + length)
    {
        // 提取 32 位数据
        uint32_t timestampValue = static_cast<uint32_t>(timestampPtr[0]) |
                                  (static_cast<uint32_t>(timestampPtr[1]) << 8) |
                                  (static_cast<uint32_t>(timestampPtr[2]) << 16) |
                                  (static_cast<uint32_t>(timestampPtr[3]) << 24);

        // std::cout << "提取的 32 位数据: 0x" << std::hex << timestampValue << std::dec << std::endl;
        // 转换为时间戳并输出
        // convertToTimestamp(timestampValue);
        // 获取当前时间戳（以秒为单位）
        time_t currentTime = time(nullptr);
        uint32_t timestampAsUInt = static_cast<uint32_t>(currentTime);
        // std::cout << "提取的current Time 32 位数据: 0x" << std::hex << timestampAsUInt << std::dec << std::endl;

        // convertToTimestamp(timestampAsUInt);

        // 睡眠10秒
        //        std::this_thread::sleep_for(std::chrono::seconds(10));
        if (timestampValue + 16 < timestampAsUInt)
        {
            std::cout << "时间戳超时" << std::endl;
            return false;
        }
        return true;
    }
}

bool verify_sequnce(const uint8_t *data, size_t length)
{
    // 跳过 0x1ACFFC1D 以及后面9个字节
    return true;
    const uint8_t *sequnce = data + 4 + 4 + 1;
    if (sequnce + 3 < data + length)
    {
        // 提取 32 位数据
        uint32_t sequnceValue = static_cast<uint32_t>(sequnce[0]) |
                                (static_cast<uint32_t>(sequnce[1]) << 8) |
                                (static_cast<uint32_t>(sequnce[2]) << 16) |
                                (static_cast<uint32_t>(sequnce[3]) << 24);

        // std::cout << "提取的 32 位数据: " << sequnceValue << std::endl;

        std::ifstream recordFile("record.txt");
        uint32_t recordedValue = 0;
        bool fileExists = false;

        if (recordFile)
        {
            fileExists = true;
            recordFile >> recordedValue;
            recordFile.close();
        }

        bool result = true;
        if (fileExists && sequnceValue >= recordedValue)
        {
            result = false;
        }

        std::ofstream outFile("record.txt");
        if (outFile)
        {
            outFile << sequnceValue;
            outFile.close();
        }
        else
        {
            std::cerr << "无法写入 record.txt 文件" << std::endl;
        }
        if (!result)
        {
            std::cout << "序号错误" << std::endl;
        }
        return result;
    }
    return false; // 如果数据长度不足，返回 false
}

bool verify_sig(const uint8_t *data, const uint8_t *checksum, int id)
{
    // std::cout << "checksum打印=====: ";
    // std::cout << std::hex; // 设置输出为十六进制格式
    //    for(int i = 0; i < 32; i++) {
    //        std::cout << static_cast<int>(checksum[i]) << " ";
    //    }
    //    std::cout << std::dec << std::endl; // 恢复输出为十进制格式
    // 检查 checksum 是否在数据范围内
    if (checksum < data)
    {
        std::cout << "checksum 位置超出数据范围，不存在。" << std::endl;
        return false;
    }

    const uint8_t *tcp_data_start = data + 4 + 1 + 4 + 4;
    // 检查 tcp_data_start 是否超出数据范围
    if (tcp_data_start >= checksum)
    {
        std::cout << "TCP 数据起始位置超出数据范围，数据部分为空。" << std::endl;
        return false;
    }

    const uint8_t *tcp_data_end = checksum;
    const size_t tcp_data_len = tcp_data_end - tcp_data_start;

    // 检查 tcp_data_len 是否为 0
    if (tcp_data_len == 0)
    {
        std::cout << "TCP 数据长度为 0，数据部分为空。" << std::endl;
        return false;
    }

    // 动态分配内存来存储 TCP 数据
    char *tcp_data = new char[tcp_data_len];
    if (tcp_data == nullptr)
    {
        std::cout << "内存分配失败。" << std::endl;
        return false;
    }

    // 复制数据
    memcpy(tcp_data, tcp_data_start, tcp_data_len);

    // 生成校验码
    //    HMACResult newResult = gen_hmac(id, tcp_data);
    char public_key_file[100];
    char private_key_file[100];
    // 生成签名
    unsigned int sig_len = 32;
    snprintf(public_key_file, sizeof(public_key_file), "%d_public_key.pem", id);

    // 1. 读取密钥对
    EVP_PKEY *verify_key = read_public_key(public_key_file);

    // 动态分配内存来存储 TCP 数据
    unsigned char *checksumData = new unsigned char[32];
    if (checksumData == nullptr)
    {
        std::cout << "内存分配失败。" << std::endl;
        return false;
    }

    // 复制数据
    memcpy(checksumData, checksum, 32);
    //    verifySignature(verify_key, tcp_data, checksum);
    //    unsigned char* hash = generate_sha("HELLO WORLD");
    //    bool result = verifySignature(verify_key, "HELLO WORLD", checksumData);
    //    if(result) {
    //        std::cout << "校验签名成功" << std::endl;
    //    } else {
    //        std::cout << "校验签名失败" << std::endl;
    //    }
    //
    //    // 释放动态分配的内存
    //    delete[] tcp_data;
    //    delete[] checksumData;
    //

    return true;
}

bool verify_hmac(const uint8_t *data, const uint8_t *checksum, int id, const uint8_t* tcpStart, size_t tcplen)
{

    // 检查 checksum 是否在数据范围内
    if (checksum < data)
    {
        std::cout << "checksum 位置超出数据范围，不存在。" << std::endl;
        return false;
    }

   
    // std::cout << "tcp data (hex): ";

    // std::cout << "len:" << tcplen << " ";
    // std::cout << std::hex; // 设置输出为十六进制格式

    // for (int i = 0; i < tcplen; i++)
    // {
    //     std::cout << static_cast<int>(tcpStart[i]) << " ";
    // }
    // std::cout << std::endl;

    // 动态分配内存来存储 TCP 数据
    char *tcp_data = new char[tcplen];

    if (tcp_data == nullptr)
    {
        std::cout << "内存分配失败。" << std::endl;
        return false;
    }

    // 复制数据
    memcpy(tcp_data, tcpStart, tcplen);

    // 生成校验码
    HMACResult newResult = gen_hmac(id, tcp_data);

    // 释放动态分配的内存
    delete[] tcp_data;
    // 比较 newResult.digest 和 checksum 的 32 位
    bool isMatch = true;
    // std::cout << "checksum data (hex): ";

    for (int i = 0; i < 32; ++i)
    {
        if (newResult.digest[i] != static_cast<char>(checksum[i]))
        {
            isMatch = false;
            break;
        }
        // std::cout << static_cast<int>(checksum[i]) << " ";
    }

    if (!isMatch)
    {
        //std::cout << "校验和验证失败。" << std::endl;
        return false;
    }
    
    return true;
}

bool verify_IP(int id)
{
    return true;
}

bool verify_IPandCheckSum(pcpp::RawPacket rawPacket, const uint8_t *data, size_t length)
{
    bool result = true;
    // 跳过 0x1ACFFC1D 以及后面4个字节
    const uint8_t *sequnce = data + 4;
    // 检查数据长度是否足够
    if (sequnce >= data + length)
    {
        std::cerr << "数据长度不足，无法提取数据。" << std::endl;
        return false;
    }
    // 提取 校验码标识
    int flag = static_cast<int>((*sequnce >> 7) & 0x01);
    // std::cout << "提取的 1 位数据: " << flag << std::endl;
    // 获取 checksum
    const uint8_t *temp = rawPacket.getRawData();
    size_t tempLen = rawPacket.getRawDataLen();
    const uint8_t *found_end = find_end_ptr(temp, tempLen);

    
    data = find_start_ptr(temp,tempLen);


    const uint8_t *checksum = found_end - 32;
    const uint8_t * tcpStart = data + 17;
    size_t tcplen = checksum - data - 17;
    


    // std::cout << "checksum data (hex): ";
    // std::cout << std::hex; // 设置输出为十六进制格式

    // for (int i = 0; i < 32; i++)
    // {
    //     std::cout << static_cast<int>(checksum[i]) << " ";
    // }
    
    // 提取 卫星ID
    int id = static_cast<int>(*sequnce & 0x7F);
    // std::cout << "提取的 7 位卫星 ID（十进制）: " << id << std::endl;
    // std::cout << "提取的flag（十进制）: " << flag << std::endl;

    if (checksum > data)
    {

        if (flag == 0)
        {
            result = verify_hmac(data, checksum, id, tcpStart, tcplen);

        }
        else if (flag == 1)
        {
            // FIXME: 签名长度太长，暂时都用hmac
            result = verify_hmac(data, checksum, id, tcpStart, tcplen);
            
        }
    }

    return verify_IP(id) && result;
}

bool verify_raw_packet(pcpp::RawPacket rawPacket)
{
    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    const uint8_t *temp = rawPacket.getRawData();
    size_t tempLen = rawPacket.getRawDataLen();
    // std::cout << std::dec <<"templen:            " <<  tempLen <<std::endl;
    // 以十六进制形式打印结果
    // std::cout << "Combined data (hex): ";
    // std::cout << std::hex; // 设置输出为十六进制格式

    // for (int i = 0; i < tempLen; i++)
    // {
    //     std::cout << static_cast<int>(temp[i]) << " ";
    // }
    // std::cout << std::dec << std::endl; // 恢复输出为十进制格式
    const uint8_t *found = find_start_ptr(temp, tempLen);

    if (!found)
    {
        // std::cout << "未找到模式 0x1ACFFC1D" << std::endl;
        return false;
    }
    // ccsds长度
    size_t ccsdsLen = tempLen - (found - temp);
    // std::cout <<"time:        " <<verify_timestamp(found, ccsdsLen) << std::endl;
    // std::cout << "seq          " <<verify_sequnce(found, ccsdsLen) << std::endl;
    // std::cout << "ip            "<<verify_IPandCheckSum(rawPacket, found, ccsdsLen) << std::endl;
    return verify_timestamp(found, ccsdsLen) && verify_sequnce(found, ccsdsLen) && verify_IPandCheckSum(rawPacket, found, ccsdsLen);
}
