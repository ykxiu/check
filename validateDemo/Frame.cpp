#include "Frame.h"
#include <iostream>


void serializeFrame(const Frame& frame, char* buffer) {
    memcpy(buffer, &frame, sizeof(Frame));
}

void deserializeFrame(const uint8_t* buffer, Frame& frame) {
    memcpy(&frame, buffer, sizeof(Frame));
}

void showFrame(const Frame &f){
    std::cout << std::hex << f.synWord << std::endl;
    std::cout << std::hex << f.checkSum << std::endl;
    std::cout << std::hex << f.flag_satelliId << std::endl;
    std::cout << "frame :"  << std::endl;
    std::cout << std::hex << f.timestamp << std::endl;
    std::cout << std::hex << f.randomN << std::endl;
    std::cout << std::endl;
}
void verifyFrame(Frame& frame) {
    // 检测时间戳
    // 检测随机数
    // 检测校验码

    
}





