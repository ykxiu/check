#include <iostream>
#include <zmq.hpp>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"

using namespace pcpp;

void onPacketArrives(pcpp::RawPacket *rawPacket, pcpp::PcapLiveDevice *dev, void *userData)
{
    zmq::socket_t *zmqSocket = reinterpret_cast<zmq::socket_t *>(userData);

    const uint8_t *data = rawPacket->getRawData();
    uint32_t dataLen = rawPacket->getRawDataLen();

    timespec tsSpec = rawPacket->getPacketTimeStamp();
    timeval ts;
    ts.tv_sec = tsSpec.tv_sec;
    ts.tv_usec = tsSpec.tv_nsec / 1000;

    uint32_t sec = ts.tv_sec;
    uint32_t usec = ts.tv_usec;

    // 创建消息体：len (4 bytes) + sec (4 bytes) + usec (4 bytes) + data
    size_t totalSize = sizeof(uint32_t) * 3 + dataLen;
    // std::cout << totalSize;
    zmq::message_t message(totalSize);

    uint8_t *buffer = static_cast<uint8_t *>(message.data());
    memcpy(buffer, &dataLen, sizeof(uint32_t));
    memcpy(buffer + 4, &sec, sizeof(uint32_t));
    memcpy(buffer + 8, &usec, sizeof(uint32_t));
    memcpy(buffer + 12, data, dataLen);

    try
    {
        zmqSocket->send(std::move(message), zmq::send_flags::none);
        //std::cout << "RawPacket sent successfully" << std::endl;
    }
    catch (const zmq::error_t &e)
    {
        std::cerr << "ZeroMQ send failed: " << e.what() << std::endl;
    }
}

int main()
{

    zmq::context_t context(1);
    zmq::socket_t queue_psh(context, ZMQ_PUSH);
    queue_psh.bind("tcp://*:9909");

    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("ens33");

    if (dev == nullptr)
    {
        std::cerr << "No default device found" << std::endl;
        return 1;
    }

    std::cout << "Using device: " << dev->getName() << std::endl;

    if (!dev->open())
    {
        std::cerr << "Could not open device" << std::endl;
        return 1;
    }

    if (!dev->setFilter("src host 192.168.216.1 and port 8888"))
    {
    std::cerr << "Failed to set filter" << std::endl;
    return 1;
    }
    // 开始捕获
    dev->startCapture(onPacketArrives, &queue_psh);

    std::cin.get();
    dev->stopCapture();
    dev->close();

    return 0;
}