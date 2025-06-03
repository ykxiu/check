// #include <zmq.hpp>
// #include <iostream>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>

// int main()
// {
//     zmq::context_t context(1);
//     zmq::socket_t queue_pll(context, ZMQ_PULL);
//     zmq::socket_t queue_out(context, ZMQ_PUSH);
//     queue_pll.connect("tcp://localhost:9919");
//     queue_out.connect("tcp://192.168.216.1:9999");
//     int cout=0;
//     std::cout << "waiting" << std::endl;
//     bool flag = true;
//     std::chrono::high_resolution_clock::time_point start_time;
//     while (true)
//     {
//         zmq::message_t message;
//         queue_pll.recv(message, zmq::recv_flags::none);
//         // queue_out.send(message,zmq::send_flags::none);
//         if(flag){
//             start_time = std::chrono::high_resolution_clock::now();
//             flag = false;
//         }
//         cout++;
//         if(cout % 1000 == 0){
//             auto curr_time = std::chrono::high_resolution_clock::now();
//             auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(curr_time-start_time);
//             std::cout << "during time" << duration.count() <<std::endl;
//         }

//     }
// }

#include <zmq.hpp>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <cstring>

int main()
{
    zmq::context_t context(1);
    zmq::socket_t queue_pll(context, ZMQ_PULL);
    queue_pll.connect("tcp://localhost:9919");

    // 创建 UDP 套接字
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0)
    {
        std::cerr << "无法创建UDP socket" << std::endl;
        return -1;
    }

    // 设置目标地址
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(9999);
    inet_pton(AF_INET, "192.168.216.1", &target_addr.sin_addr);

    int count = 0;
    std::cout << "waiting" << std::endl;

    while (true)
    {
        zmq::message_t message;
        queue_pll.recv(message, zmq::recv_flags::none);

        const uint8_t *buffer = static_cast<const uint8_t *>(message.data());
        uint32_t dataLen;
        memcpy(&dataLen, buffer, sizeof(uint32_t));
        const uint8_t *data = buffer + 12 + 42;

        ssize_t sent = sendto(udp_socket,
                              data,
                              dataLen - 42, 
                              0,
                              (struct sockaddr *)&target_addr,
                              sizeof(target_addr));

        if (sent == -1)
        {
            std::cerr << "UDP发送失败" << std::endl;
        }
    }

    close(udp_socket);
    return 0;
}
