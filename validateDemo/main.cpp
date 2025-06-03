#include <iostream>
#include <zmq.hpp>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include "Frame.h"
#include <chrono>

bool verify_raw_packet(pcpp::RawPacket rawPacket);

int main()
{
    zmq::context_t context(1);
    zmq::socket_t queue_psh(context, ZMQ_PULL);
    zmq::socket_t queue_pll(context, ZMQ_PUSH);
    queue_psh.connect("tcp://localhost:9909");
    queue_pll.bind("tcp://*:9919");
    int succ_count = 0;
    bool flag = true;
    std::chrono::high_resolution_clock::time_point start_time;
    while (1)
    {
        zmq::message_t message;
        if (queue_psh.recv(message, zmq::recv_flags::none))
        {
            const uint8_t *buffer = static_cast<const uint8_t *>(message.data());

            uint32_t dataLen;
            uint32_t sec;
            uint32_t usec;

            memcpy(&dataLen, buffer, sizeof(uint32_t));
            memcpy(&sec, buffer + 4, sizeof(uint32_t));
            memcpy(&usec, buffer + 8, sizeof(uint32_t));

            const uint8_t *data = buffer + 12;

            timeval timestamp;
            timestamp.tv_sec = sec;
            timestamp.tv_usec = usec;

            pcpp::RawPacket rawPacket(data, dataLen, timestamp, false);
            pcpp::Packet parsedPacket(&rawPacket);

            if (parsedPacket.isPacketOfType(pcpp::IPv4) && parsedPacket.isPacketOfType(pcpp::UDP))
            {

                // auto tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                // uint8_t *str = tcpLayer->getLayerPayload();
                // size_t strlen = tcpLayer->getLayerPayloadSize();

                // std::cout << "str data (hex): ";
                // std::cout << std::hex; // 设置输出为十六进制格式

                // for (int i = 0; i <strlen; i++)
                // {
                //     std::cout << static_cast<int>(str[i]) << " ";
                // }
                // std::cout << std::endl;

                // Frame *frame = new Frame;
                // deserializeFrame(str, *frame);
                // showFrame(*frame);

                // if(flag){
                //     start_time = std::chrono::high_resolution_clock::now();
                //     flag = false;
                // }

                static int success_count = 0;
                static int fail_count = 0;
                static bool is_first = true;
                static std::chrono::high_resolution_clock::time_point start_time;

                if (verify_raw_packet(rawPacket))
                {
                    // succ_count++;
                    // if(succ_count % 1000 == 0){
                    //     auto curr_time = std::chrono::high_resolution_clock::now();
                    //     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(curr_time-start_time);
                    //     std::cout << "during time" << duration.count() <<std::endl;
                    // }
                    // std::cout <<succ_count << "校验成功, " << "放入队列中" << std::endl;
                    // 直接将message送入发送队列，如果验证成功此时的message应该也是正确的
                    queue_pll.send(std::move(message), zmq::send_flags::none);
                    if (is_first)
                    {
                        start_time = std::chrono::high_resolution_clock::now();
                        is_first = false;
                    }
                    success_count++;
                }
                else
                {
                    fail_count++;
                }
                if (success_count + fail_count >= 2000)
                {
                    auto end_time = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                    std::cout << "统计信息：" << std::endl;
                    std::cout << "成功包数: " << success_count << std::endl;
                    std::cout << "失败包数: " << fail_count << std::endl;
                    std::cout << "总耗时: " << duration.count() << " 毫秒" << std::endl;
                    std::cout << "平均处理时间: " << (float)duration.count() / (success_count + fail_count) << " 毫秒/包" << std::endl;

                    // 重置计数器
                    success_count = 0;
                    fail_count = 0;
                    is_first = true;
                }
            }
        }
    }
}