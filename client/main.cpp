
#include "ItemList.hpp"
#include "TCPClientManager.hpp"

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>










int main(void)
{
    // create some items to send
    std::shared_ptr<StreamableItemList> list = StreamableItemList::createItemList();
    list->addStoredItem("Mary", {24, 28, 92, 34, 32}, {.52, 532.563, 63.34, 935.74}, 90, 5353456, false);
    list->addStoredItem("Tom", {63,32, 64}, {0.345, 0.9885, 995634.3, 934.345}, 80, 53453, true);
    list->addStoredItem("Raene", {3, 6, 9}, {0.634, 964, 923.24, 9643.2}, 96, 952326, false);
    list->addStoredItem("Lee", {60, 3, 6}, {}, 24, 34634, true); 

    TCPClientManager tcp_manager("192.168.68.52", "1234", "ca.pem", list, 2);
    tcp_manager.run();
    return 0;
}

