#pragma once
#include <cstdint>
#include <cstring>


#pragma pack(1)
struct Frame {
    
    unsigned int synWord : 32; // 帧同步字 (32 bit)
    unsigned char checkSum[32]; //校验码:0是HAMC校验码，1是数字签名值
    unsigned int endWord : 32; //定位符
    unsigned int timestamp : 32; //时间戳
    unsigned int randomN : 32; //序号
    unsigned int flag_satelliId : 8; //checkFlag + 航天器ID (8 bit)

    // Frame() :
    //     synWord(0x1ACFFC1D),
    //     flag_satelliId(0b10000111),
    //     timestamp(0b00),
    //     randomN(0x00000000),
    //     endWord(0x1ACFFC1E) // 假设定位符
    // {
    //     // 初始化 checkSum 数组
    //     for (int i = 0; i < 32; i++) {
    //         checkSum[i] = 1;
    //     }
    // }

};
#pragma pack()

void serializeFrame(const Frame& frame, char* buffer);

void deserializeFrame(const uint8_t* buffer, Frame& frame);

void showFrame(const Frame &f);